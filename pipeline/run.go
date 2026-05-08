package pipeline

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

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

	if !cfg.NoAutoFilter {
		fmt.Println("[*] Running Ghost-Smart Pre-Checks (V5)...")

		if cfg.ReqConfig.WAFBypassLevel >= 3 {
			fmt.Println("[*] Attempting Origin IP Discovery (WAF Bypass)...")
			if origin, err := discovery.SeekOrigin(ctx, cfg.TargetURL, cfg.ReqConfig); err == nil && origin.IsBypassed {
				fmt.Printf("[+] Found Origin IP: %s (content-verified). Switching to direct connection.\n", origin.OriginIP)
				cfg.TargetURL = "https://" + origin.OriginIP
			}
		}

		if err := checkReachability(ctx, cfg.ReqConfig, cfg.TargetURL); err != nil {
			return nil, fmt.Errorf("pre-check failed: target is unreachable (%v)", err)
		}

		fmt.Println("[*] Calibrating Dynamic Wildcards (Multi-Sampling)...")
		calibrations := calibrateTarget(ctx, cfg.ReqConfig, cfg.TargetURL)
		if len(calibrations) > 0 {

			canExcludeCodes := cfg.StatusCodes == ""

			// Check if any calibrated wildcard status overlaps with user's --status-codes.
			// If so, we must enable --force (wildcard mode) to prevent gobuster from refusing to run.
			wildcardConflict := false
			if cfg.StatusCodes != "" {
				userCodes := strings.Split(cfg.StatusCodes, ",")
				for _, cal := range calibrations {
					calCode := fmt.Sprintf("%d", cal.Status)
					for _, uc := range userCodes {
						if strings.TrimSpace(uc) == calCode {
							wildcardConflict = true
							break
						}
					}
					if wildcardConflict {
						break
					}
				}
			}

			for _, cal := range calibrations {
				if canExcludeCodes {
					if cfg.ExcludeCodes == "" {
						cfg.ExcludeCodes = fmt.Sprintf("%d", cal.Status)
					} else if !strings.Contains(cfg.ExcludeCodes, fmt.Sprintf("%d", cal.Status)) {
						cfg.ExcludeCodes += fmt.Sprintf(",%d", cal.Status)
					}
				}

				lenStr := fmt.Sprintf("%d", cal.Length)
				if cfg.ExcludeLength == "" {
					cfg.ExcludeLength = lenStr
				} else if !strings.Contains(cfg.ExcludeLength, lenStr) {
					cfg.ExcludeLength += "," + lenStr
				}
			}

			if wildcardConflict {
				cfg.Wildcard = true
				fmt.Printf("[!] Wildcard response detected with status code in --status-codes. Enabling --force mode.\n")
			}
			fmt.Printf("[+] Auto-Filter: Calibrated %d dynamic wildcard profile(s).\n", len(calibrations))
		}
	}

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

		if !discovery.InScope(cfg.TargetURL, u) {
			fmt.Printf("[!] Skipping out-of-scope URL: %s\n", u)
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

	bypassHeaders := reqconfig.GetBypassHeaders(cfg.ReqConfig.WAFBypassLevel)

	args := buildGobusterArgs(cfg, wlPath, bypassHeaders)
	hits, err := runner.CollectHits(ctx, gobusterexec.ModeDir, args, os.Stderr)
	if err != nil {
		ro.GobusterError = err.Error()
	}

	hits = filterHitsInScope(cfg.TargetURL, hits)

	client, clientErr := reqconfig.NewClient(cfg.ReqConfig)
	if clientErr == nil {

		hits = validateHits(ctx, client, cfg.TargetURL, hits)
	}
	ro.Hits = hits
	ro.Parsed = ParseHits(hits)
	ro.Analysis = responseanalyze.Analyze(HitsToSamples(hits), cfg.Analyze)

	if clientErr == nil {
		_ = os.MkdirAll("loot", 0755)
		seenTechs := make(map[string]bool)
		var allTechs []fingerprint.TechResult
		var allCVEs []cve.Result

		for _, h := range hits {
			fullURL := h.Path
			if !strings.HasPrefix(fullURL, "http") {
				fullURL, _ = joinTarget(cfg.TargetURL, h.Path)
			}

			if !discovery.InScope(cfg.TargetURL, fullURL) {
				continue
			}

			if h.StatusCode != nil && *h.StatusCode == 403 && cfg.ReqConfig.WAFBypassLevel >= 3 {
				for _, method := range []string{"POST", "HEAD", "OPTIONS"} {
					body, _, err := fetchWithMethod(ctx, client, method, fullURL)
					if err == nil && len(body) > 0 {
						h.Path += fmt.Sprintf(" [%s Bypass]", method)
						saveLoot(h.Path, body)
						break
					}
				}
			}

			isSensitive := false
			for _, ext := range []string{".env", ".git", ".bash_history", ".sql", ".bak", ".config"} {
				if strings.Contains(strings.ToLower(h.Path), ext) {
					isSensitive = true
					break
				}
			}

			if h.StatusCode != nil && *h.StatusCode == 200 {
				body, headers, err := fetchBody(ctx, client, fullURL)
				if err != nil {
					continue
				}

				if isSensitive {
					saveLoot(h.Path, body)
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

			u, err := joinTarget(cfg.TargetURL, a.Key)
			if err != nil || !discovery.InScope(cfg.TargetURL, u) {
				continue
			}
			n, _ := q.PushExpanded(a.Key, cfg.Discovery)
			queued += n
		}
	}
	if cfg.SeedFromAllHits {
		for _, h := range hits {
			u, err := joinTarget(cfg.TargetURL, h.Path)
			if err != nil || !discovery.InScope(cfg.TargetURL, u) {
				continue
			}
			n, _ := q.PushExpanded(h.Path, cfg.Discovery)
			queued += n
		}
	}
	ro.DiscoveredQueued = queued
	return ro, nil
}

func filterHitsInScope(targetURL string, hits []gobusterexec.Hit) []gobusterexec.Hit {
	out := make([]gobusterexec.Hit, 0, len(hits))
	for _, h := range hits {
		fullURL := h.Path
		if !strings.HasPrefix(fullURL, "http") {
			var err error
			fullURL, err = joinTarget(targetURL, h.Path)
			if err != nil {
				continue
			}
		}
		if discovery.InScope(targetURL, fullURL) {
			out = append(out, h)
		}
	}
	return out
}

func fetchBody(ctx context.Context, client *http.Client, url string) ([]byte, http.Header, error) {
	return fetchWithMethod(ctx, client, "GET", url)
}

func fetchWithMethod(ctx context.Context, client *http.Client, method, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	return body, resp.Header, err
}

func validateHits(ctx context.Context, client *http.Client, target string, hits []gobusterexec.Hit) []gobusterexec.Hit {
	valid := make([]gobusterexec.Hit, 0, len(hits))
	for _, h := range hits {
		fullURL := h.Path
		if !strings.HasPrefix(fullURL, "http") {
			var err error
			fullURL, err = joinTarget(target, h.Path)
			if err != nil {
				continue
			}
		}

		status1, length1, err := fetchStatusLength(ctx, client, fullURL)
		if err != nil {
			continue
		}
		status2, length2, err := fetchStatusLength(ctx, client, fullURL)
		if err != nil {
			continue
		}

		if status1 != status2 || length1 != length2 {
			continue
		}

		if h.StatusCode != nil && *h.StatusCode != status1 {
			continue
		}

		h.StatusCode = intPtr(status1)
		h.Size = int64Ptr(int64(length1))
		valid = append(valid, h)
	}
	return valid
}

func fetchStatusLength(ctx context.Context, client *http.Client, url string) (int, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return 0, 0, err
	}
	return resp.StatusCode, len(body), nil
}

func intPtr(v int) *int {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func saveLoot(path string, body []byte) {
	safeName := strings.ReplaceAll(path, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	if len(safeName) > 200 {
		safeName = safeName[:200]
	}
	_ = os.WriteFile("loot/"+safeName, body, 0644)
}

func buildGobusterArgs(cfg *Config, wordlistPath string, bypassHeaders map[string]string) []string {
	args := make([]string, 0, 10+len(cfg.GobusterExtraArgs)+len(bypassHeaders)*2)
	args = append(args, "dir", "-u", cfg.TargetURL, "-w", wordlistPath)
	for k, v := range bypassHeaders {
		args = append(args, "-H", k+": "+v)
	}

	if cfg.StatusCodes != "" {
		args = append(args, "-s", cfg.StatusCodes)

		if cfg.ExcludeCodes == "" {
			args = append(args, "-b", "")
		}
	}
	if cfg.ExcludeCodes != "" {
		args = append(args, "-b", cfg.ExcludeCodes)
	}

	if cfg.ExcludeLength != "" {
		args = append(args, "--exclude-length", cfg.ExcludeLength)
	}
	if cfg.Wildcard {
		args = append(args, "--force")
	}
	if cfg.Extensions != "" {
		args = append(args, "-x", cfg.Extensions)
	}
	if cfg.AddSlash {
		args = append(args, "-f")
	}
	if cfg.Recursive || cfg.Depth > 1 {
		args = append(args, "--recursive")
		if cfg.Depth > 0 {
			args = append(args, "--depth", fmt.Sprintf("%d", cfg.Depth))
		}
	}
	args = append(args, cfg.GobusterExtraArgs...)
	return args
}

func checkReachability(ctx context.Context, reqCfg reqconfig.Config, target string) error {
	client, err := reqconfig.NewClient(reqCfg)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

type CalibrationProfile struct {
	Status int
	Length int
}

func calibrateTarget(ctx context.Context, reqCfg reqconfig.Config, target string) []CalibrationProfile {
	client, err := reqconfig.NewClient(reqCfg)
	if err != nil {
		return nil
	}

	type profileCount struct {
		profile CalibrationProfile
		count   int
	}
	counts := make(map[string]*profileCount)

	const probes = 10
	for i := 0; i < probes; i++ {

		randPath := fmt.Sprintf("/obscura-calibrate-%d-%d", rand.Intn(1_000_000), rand.Intn(1_000_000))
		u := strings.TrimSuffix(target, "/") + randPath

		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()

		key := fmt.Sprintf("%d:%d", resp.StatusCode, len(body))
		if pc, ok := counts[key]; ok {
			pc.count++
		} else {
			counts[key] = &profileCount{
				profile: CalibrationProfile{Status: resp.StatusCode, Length: len(body)},
				count:   1,
			}
		}

		time.Sleep(150 * time.Millisecond)
	}

	var profiles []CalibrationProfile
	for _, pc := range counts {
		if pc.count >= 2 {
			profiles = append(profiles, pc.profile)
		}
	}
	return profiles
}
