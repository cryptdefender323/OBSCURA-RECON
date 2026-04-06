package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"obscura/pipeline"
	"obscura/report"
)

func main() {
	target := pflag.StringP("url", "u", "", "Target URL (e.g. https://example.com)")
	wordlist := pflag.StringP("wordlist", "w", "", "Base wordlist file")
	rounds := pflag.IntP("rounds", "r", 3, "Max rounds of discovery")
	pdfPath := pflag.String("report-pdf", "report.pdf", "Output path for PDF report")
	wafLevel := pflag.Int("waf-level", 0, "WAF Bypass Level (0:None, 1:Basic, 2:Advanced, 3:Full Encode)")
	statusCodes := pflag.String("status-codes", "", "Status codes to include (e.g. 200,204,301)")
	excludeCodes := pflag.String("exclude-codes", "", "Status codes to exclude (e.g. 403,404)")
	excludeLength := pflag.String("exclude-length", "", "Excluded response lengths (e.g. 421,0)")
	wildcard := pflag.Bool("wildcard", false, "Force continue if wildcard response is detected")
	pflag.Parse()

	if *target == "" || *wordlist == "" {
		pflag.Usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := pipeline.DefaultConfig()
	cfg.TargetURL = *target
	cfg.BaseWordlistPath = *wordlist
	cfg.MaxRounds = *rounds
	cfg.ReqConfig.WAFBypassLevel = *wafLevel
	cfg.Wordlist.WAFBypassLevel = *wafLevel
	cfg.StatusCodes = *statusCodes
	cfg.ExcludeCodes = *excludeCodes
	cfg.ExcludeLength = *excludeLength
	cfg.Wildcard = *wildcard

	fmt.Printf("[*] Starting Obscura Recon on %s\n", *target)
	fmt.Printf("[*] Rounds: %d, Wordlist: %s\n", *rounds, *wordlist)

	res, err := pipeline.Run(ctx, cfg)
	if err != nil {
		log.Fatalf("Error running pipeline: %v", err)
	}

	fmt.Println("[+] Scan complete. Generating report...")

	reportData := report.Data{
		TargetURL: *target,
		Rounds:    len(res.Rounds),
	}

	for _, ro := range res.Rounds {
		reportData.TotalHits += len(ro.Hits)
		reportData.Hits = append(reportData.Hits, ro.Hits...)

		for _, t := range ro.Techs {
			tech := report.TechInfo{
				Name:     t.Name,
				Version:  t.Version,
				Category: t.Category,
			}

			for _, c := range ro.CVEs {
				if c.TechName == t.Name {
					for _, v := range c.CVEs {
						tech.CVEs = append(tech.CVEs, report.CVEInfo{
							ID:          v.ID,
							Description: v.Description,
							Severity:    v.Severity,
						})
					}
				}
			}
			reportData.Technologies = append(reportData.Technologies, tech)
		}

		for _, a := range ro.Analysis.Anomalies {
			reportData.Anomalies = append(reportData.Anomalies, report.AnomalyInfo{
				Path:   a.Key,
				Reason: a.Reason,
			})
		}
	}

	if err := report.GeneratePDF(*pdfPath, reportData); err != nil {
		log.Fatalf("Error generating report: %v", err)
	}

	fmt.Printf("[+] Professional PDF report generated: %s\n", *pdfPath)
}
