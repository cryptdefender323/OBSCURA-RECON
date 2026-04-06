package pipeline

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	"obscura/cve"
	"obscura/discovery"
	"obscura/fingerprint"
	"obscura/gobusterexec"
	"obscura/gobusterparse"
	"obscura/reqconfig"
	"obscura/responseanalyze"
	"obscura/wordlistgen"
)

type RunResult struct {
	Rounds []RoundOutcome
}

type RoundOutcome struct {
	Round            int
	WordCount        int
	Hits             []gobusterexec.Hit
	Parsed           []gobusterparse.Record
	Analysis         responseanalyze.Result
	Techs            []fingerprint.TechResult
	CVEs             []cve.Result
	DiscoveredQueued int
	GobusterError    string
}

func Run(ctx context.Context, cfg Config) (*RunResult, error) {
	cfg.normalize()
	if cfg.TargetURL == "" {
		return nil, ErrNoTarget
	}

	baseLines, err := loadBaseLines(&cfg)
	if err != nil {
		return nil, err
	}

	q := discovery.NewScanQueue()
	runner := gobusterexec.NewRunner(cfg.GobusterPath)
	out := &RunResult{}

	for r := 0; r < cfg.MaxRounds; r++ {
		if r > 0 && q.Len() == 0 {
			break
		}

		if r == 0 {
			ro := RoundOutcome{Round: -1}
			client, err := reqconfig.NewClient(cfg.ReqConfig)
			if err == nil {
				body, headers, err := fetchBody(ctx, client, cfg.TargetURL)
				if err == nil {
					res := fingerprint.Analyze(headers, body, fingerprint.DefaultSignatures)
					ro.Techs = res.Techs
					for _, t := range res.Techs {
						ro.CVEs = append(ro.CVEs, cve.Lookup(t.Name, t.Version))
					}
				}
			}
			out.Rounds = append(out.Rounds, ro)
		}

		ro, err := runRound(ctx, r, &cfg, baseLines, q, runner)
		if err != nil {
			return out, err
		}
		out.Rounds = append(out.Rounds, ro)
	}

	return out, nil
}

func loadBaseLines(cfg *Config) ([]string, error) {
	if len(cfg.BaseLines) > 0 {
		return cfg.BaseLines, nil
	}
	if cfg.BaseWordlistPath == "" {
		return nil, ErrNoWordlist
	}
	f, err := os.Open(cfg.BaseWordlistPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return wordlistgen.ReadLines(f)
}

func runRound(ctx context.Context, round int, cfg *Config, base []string, q *discovery.ScanQueue, runner *gobusterexec.Runner) (RoundOutcome, error) {
	ro := RoundOutcome{Round: round}

	urls := []string{cfg.TargetURL}
	for n := 0; n < cfg.MaxQueueDrain; n++ {
		p, ok := q.Pop()
		if !ok {
			break
		}
		u, err := joinTarget(cfg.TargetURL, p)
		if err != nil {
			continue
		}
		urls = append(urls, u)
	}

	words, err := wordlistgen.Build(cfg.Wordlist, base, urls, nil)
	if err != nil {
		return ro, err
	}
	ro.WordCount = len(words)

	wlPath, cleanup, err := writeWordlist(words)
	if err != nil {
		return ro, err
	}
	defer cleanup()

	args := buildGobusterArgs(cfg, wlPath)
	hits, err := runner.CollectHits(ctx, gobusterexec.ModeDir, args, os.Stderr)
	if err != nil {
		ro.GobusterError = err.Error()
	}
	ro.Hits = hits
	ro.Parsed = ParseHits(hits)
	ro.Analysis = responseanalyze.Analyze(HitsToSamples(hits), cfg.Analyze)

	client, err := reqconfig.NewClient(cfg.ReqConfig)
	if err == nil {
		seenTechs := make(map[string]bool)
		var allTechs []fingerprint.TechResult
		var allCVEs []cve.Result
		for _, h := range hits {
			if h.StatusCode != nil && *h.StatusCode == 200 {
				fullURL := h.Path
				if !strings.HasPrefix(fullURL, "http") {
					fullURL, _ = joinTarget(cfg.TargetURL, h.Path)
				}
				body, headers, err := fetchBody(ctx, client, fullURL)
				if err != nil {
					continue
				}
				res := fingerprint.Analyze(headers, body, fingerprint.DefaultSignatures)
				for _, t := range res.Techs {

					key := t.Name + ":" + t.Version
					if !seenTechs[key] {
						allTechs = append(allTechs, t)
						allCVEs = append(allCVEs, cve.Lookup(t.Name, t.Version))
						seenTechs[key] = true
					}
				}
			}
		}
		ro.Techs = allTechs
		ro.CVEs = allCVEs
	}

	queued := 0
	if cfg.SeedFromAnomalies {
		for _, a := range ro.Analysis.Anomalies {
			n, _ := q.PushExpanded(a.Key, cfg.Discovery)
			queued += n
		}
	}
	if cfg.SeedFromAllHits {
		for _, h := range hits {
			n, _ := q.PushExpanded(h.Path, cfg.Discovery)
			queued += n
		}
	}
	ro.DiscoveredQueued = queued
	return ro, nil
}

func fetchBody(ctx context.Context, client *http.Client, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return body, resp.Header, err
}

func buildGobusterArgs(cfg *Config, wordlistPath string) []string {
	args := make([]string, 0, 4+len(cfg.GobusterExtraArgs))
	args = append(args, "dir", "-u", cfg.TargetURL, "-w", wordlistPath)
	if cfg.StatusCodes != "" {
		args = append(args, "-s", cfg.StatusCodes)
	}
	if cfg.ExcludeCodes != "" {
		args = append(args, "-b", cfg.ExcludeCodes)
	}
	if cfg.ExcludeLength != "" {
		args = append(args, "--exclude-length", cfg.ExcludeLength)
	}
	if cfg.Wildcard {
		args = append(args, "--wildcard")
	}
	args = append(args, cfg.GobusterExtraArgs...)
	return args
}
