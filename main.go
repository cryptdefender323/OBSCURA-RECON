package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"obscura/banner"
	"obscura/pipeline"
	"obscura/report"
	"obscura/stats"
)

func main() {
	target := pflag.StringP("url", "u", "", "Target URL (e.g. https://example.com)")
	wordlist := pflag.StringP("wordlist", "w", "", "Base wordlist file")
	rounds := pflag.IntP("rounds", "r", 3, "Max rounds of discovery")
	pdfPath := pflag.String("report-pdf", "report.pdf", "Output path for PDF report")
	jsonPath := pflag.String("report-json", "", "Output path for JSON report (optional)")
	wafLevel := pflag.Int("waf-level", 0, "WAF Bypass Level (0:None, 1:Basic, 2:Advanced, 3:Full Encode)")
	statusCodes := pflag.String("status-codes", "", "Status codes to include (e.g. 200,204,301)")
	excludeCodes := pflag.String("exclude-codes", "", "Status codes to exclude (e.g. 403,404)")
	excludeLength := pflag.String("exclude-length", "", "Excluded response lengths (e.g. 421,0)")
	wildcard := pflag.Bool("wildcard", false, "Force continue if wildcard response is detected")
	extensions := pflag.StringP("extensions", "x", "", "File extensions to search for (e.g. php,zip)")
	depth := pflag.IntP("depth", "d", 1, "Maximum recursion depth")
	addSlash := pflag.BoolP("add-slash", "f", false, "Append / to each request")
	noAutoFilter := pflag.Bool("no-auto-filter", false, "Disable smart wildcard auto-filtering")
	pflag.Parse()

	if *target == "" || *wordlist == "" {
		pflag.Usage()
		os.Exit(1)
	}

	banner.Print()

	if *statusCodes != "" && *excludeCodes != "" {
		banner.PrintWarning("--status-codes and --exclude-codes cannot be used together (gobuster limitation)")
		banner.PrintWarning(fmt.Sprintf("Using --status-codes=%q and ignoring --exclude-codes=%q", *statusCodes, *excludeCodes))
		*excludeCodes = ""
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
	cfg.Extensions = *extensions
	cfg.Depth = *depth
	cfg.AddSlash = *addSlash
	cfg.NoAutoFilter = *noAutoFilter

	banner.PrintStats(*target, *rounds, *wordlist)

	st := stats.New(*rounds)

	res, err := pipeline.Run(ctx, cfg)
	if err != nil {
		banner.PrintError(fmt.Sprintf("Error running pipeline: %v", err))
		log.Fatalf("Error running pipeline: %v", err)
	}

	for _, ro := range res.Rounds {
		st.AddHits(len(ro.Hits))
		st.AddAnomalies(len(ro.Analysis.Anomalies))
		st.AddTechnologies(len(ro.Techs))
		for _, cve := range ro.CVEs {
			st.AddCVEs(len(cve.CVEs))
		}
	}

	st.PrintFinal()

	banner.PrintInfo("Generating reports...")

	reportData := report.Data{
		TargetURL: *target,
		Rounds:    len(res.Rounds),
	}

	for _, ro := range res.Rounds {
		reportData.TotalHits += len(ro.Hits)
		reportData.Hits = append(reportData.Hits, ro.Hits...)

		for _, t := range ro.Techs {
			tech := report.TechInfo{
				Name:       t.Name,
				Version:    t.Version,
				Category:   t.Category,
				Confidence: t.Confidence,
				Evidence:   t.Evidence,
			}

			for _, c := range ro.CVEs {
				if c.TechName == t.Name {
					for _, v := range c.CVEs {
						tech.CVEs = append(tech.CVEs, report.CVEInfo{
							ID:          v.ID,
							Description: v.Description,
							Severity:    v.Severity,
							Confidence:  v.Confidence,
							Evidence:    v.Evidence,
						})
					}
				}
			}
			reportData.Technologies = append(reportData.Technologies, tech)
		}

		for _, a := range ro.Analysis.Anomalies {
			reportData.Anomalies = append(reportData.Anomalies, report.AnomalyInfo{
				Path:       a.Key,
				Reason:     a.Reason,
				Confidence: a.Confidence,
				Evidence:   a.Evidence,
			})
		}
	}

	if err := report.GeneratePDF(*pdfPath, reportData); err != nil {
		banner.PrintError(fmt.Sprintf("Error generating PDF report: %v", err))
		log.Fatalf("Error generating PDF report: %v", err)
	}
	banner.PrintSuccess(fmt.Sprintf("PDF report generated: %s", *pdfPath))

	if *jsonPath != "" {
		if err := report.GenerateJSON(*jsonPath, reportData); err != nil {
			banner.PrintError(fmt.Sprintf("Error generating JSON report: %v", err))
			log.Fatalf("Error generating JSON report: %v", err)
		}
		banner.PrintSuccess(fmt.Sprintf("JSON report generated: %s", *jsonPath))
	}

	fmt.Println()
}
