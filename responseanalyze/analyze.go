package responseanalyze

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type clusterBucket struct {
	status  int
	bodyLen int
	hash    uint64
	keys    []string
}

func Analyze(samples []Sample, opt Options) Result {
	opt.normalize()
	keyOf := func(s Sample) string {
		ln := effectiveBodyLen(s)
		if opt.HashBodyPrefixBytes > 0 {
			h := prefixHash64(s.Body, opt.HashBodyPrefixBytes)
			return strconv.Itoa(s.Status) + ":" + strconv.Itoa(ln) + ":" + strconv.FormatUint(h, 16)
		}
		return strconv.Itoa(s.Status) + ":" + strconv.Itoa(ln)
	}

	m := make(map[string]*clusterBucket)
	order := make([]string, 0)

	for _, s := range samples {
		k := keyOf(s)
		b, ok := m[k]
		if !ok {
			var h uint64
			if opt.HashBodyPrefixBytes > 0 {
				h = prefixHash64(s.Body, opt.HashBodyPrefixBytes)
			}
			b = &clusterBucket{status: s.Status, bodyLen: effectiveBodyLen(s), hash: h}
			m[k] = b
			order = append(order, k)
		}
		b.keys = append(b.keys, s.Key)
	}

	clusters := make([]ClusterSummary, 0, len(m))
	for _, k := range order {
		b := m[k]
		pat := patternString(b.status, b.bodyLen, b.hash, opt.HashBodyPrefixBytes > 0)
		ex := pickExamples(b.keys, opt.MaxExampleKeys)
		clusters = append(clusters, ClusterSummary{
			Pattern:     pat,
			Status:      b.status,
			BodyLen:     b.bodyLen,
			Count:       len(b.keys),
			ExampleKeys: ex,
		})
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Count != clusters[j].Count {
			return clusters[i].Count > clusters[j].Count
		}
		if clusters[i].Status != clusters[j].Status {
			return clusters[i].Status < clusters[j].Status
		}
		return clusters[i].BodyLen < clusters[j].BodyLen
	})

	var similar []ClusterSummary
	for _, c := range clusters {
		if c.Count >= opt.MinSimilarCluster {
			similar = append(similar, c)
		}
	}

	anomalies := detectAnomalies(samples, m, order, keyOf, opt)

	return Result{
		Clusters:        clusters,
		SimilarClusters: similar,
		Anomalies:       anomalies,
	}
}

func patternString(status, bodyLen int, hash uint64, useHash bool) string {
	if useHash {
		return fmt.Sprintf("status=%d len=%d body_prefix_hash=%x", status, bodyLen, hash)
	}
	return fmt.Sprintf("status=%d len=%d", status, bodyLen)
}

func pickExamples(keys []string, max int) []string {
	if max == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
		if len(out) >= max {
			break
		}
	}
	return out
}

func detectAnomalies(samples []Sample, m map[string]*clusterBucket, order []string, keyOf func(Sample) string, opt Options) []Anomaly {

	dominantCountByStatus := make(map[int]int)
	for _, k := range order {
		b := m[k]
		n := len(b.keys)
		if n > dominantCountByStatus[b.status] {
			dominantCountByStatus[b.status] = n
		}
	}

	var out []Anomaly
	for _, s := range samples {
		k := keyOf(s)
		b := m[k]
		if b == nil {
			continue
		}
		selfN := len(b.keys)
		dom := dominantCountByStatus[s.Status]
		if dom < opt.MinDominantCount || selfN >= dom {
			continue
		}
		var reason string
		switch {
		case selfN == 1:
			reason = fmt.Sprintf("singleton response shape for status %d while dominant template has %d hits", s.Status, dom)
		case selfN*10 <= dom:
			reason = fmt.Sprintf("rare response shape for status %d: cluster size %d vs dominant %d (≤10%% of dominant)", s.Status, selfN, dom)
		default:
			continue
		}
		out = append(out, Anomaly{
			Key:     s.Key,
			Status:  s.Status,
			BodyLen: effectiveBodyLen(s),
			Reason:  reason,
		})
	}

	dedup := make(map[string]struct{})
	uniq := out[:0]
	for _, a := range out {
		id := a.Key + "|" + strconv.Itoa(a.Status) + "|" + strconv.Itoa(a.BodyLen)
		if _, ok := dedup[id]; ok {
			continue
		}
		dedup[id] = struct{}{}
		uniq = append(uniq, a)
	}
	return uniq
}
