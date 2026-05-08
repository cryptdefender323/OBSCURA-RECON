package pipeline

import (
	"obscura/gobusterexec"
	"obscura/gobusterparse"
	"obscura/responseanalyze"
)

func HitsToSamples(hits []gobusterexec.Hit) []responseanalyze.Sample {
	var out []responseanalyze.Sample
	for _, h := range hits {
		if h.StatusCode == nil {
			continue
		}
		s := responseanalyze.Sample{
			Key:    h.Path,
			Status: *h.StatusCode,
		}
		if h.Size != nil && *h.Size >= 0 {
			s.ReportedLength = int(*h.Size)
		}
		out = append(out, s)
	}
	return out
}

func ParseHits(hits []gobusterexec.Hit) []gobusterparse.Record {
	var out []gobusterparse.Record
	for _, h := range hits {
		if h.Raw == "" {
			continue
		}
		mode := gobusterparse.ModeDir
		if h.Mode == gobusterexec.ModeVhost {
			mode = gobusterparse.ModeVhost
		} else if h.Mode == gobusterexec.ModeDNS {
			mode = gobusterparse.ModeDNS
		}
		rec, ok := gobusterparse.ParseLine(mode, h.Raw)
		if !ok {
			continue
		}
		out = append(out, rec)
	}
	return out
}
