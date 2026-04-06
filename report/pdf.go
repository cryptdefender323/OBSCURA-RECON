package report

import (
	"fmt"
	"strings"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"obscura/gobusterexec"
)

type Data struct {
	TargetURL    string
	Rounds       int
	TotalHits    int
	Technologies []TechInfo
	Anomalies    []AnomalyInfo
	Hits         []gobusterexec.Hit
}

type TechInfo struct {
	Name     string
	Version  string
	Category string
	CVEs     []CVEInfo
}

type CVEInfo struct {
	ID          string
	Description string
	Severity    string
}

type AnomalyInfo struct {
	Path   string
	Reason string
}

func GeneratePDF(outputPath string, data Data) error {
	cfg := config.NewBuilder().
		Build()

	m := maroto.New(cfg)

	headerColor := &props.Color{Red: 15, Green: 35, Blue: 75}
	accentColor := &props.Color{Red: 200, Green: 160, Blue: 50}
	dangerColor := &props.Color{Red: 180, Green: 0, Blue: 0}
	white := &props.Color{Red: 255, Green: 255, Blue: 255}

	m.AddRows(row.New(30).Add(
		col.New(12).Add(
			text.New("OBSCURA RECON: SECURITY ASSESSMENT", props.Text{
				Size:  20,
				Style: fontstyle.Bold,
				Align: align.Center,
				Color: white,
			}),
		).WithStyle(&props.Cell{BackgroundColor: headerColor}),
	))

	m.AddRows(row.New(10))

	riskScore := calculateRisk(data)
	riskText := "LOW"
	riskColor := &props.Color{Red: 0, Green: 150, Blue: 0}
	if riskScore > 7 {
		riskText = "CRITICAL"
		riskColor = dangerColor
	} else if riskScore > 4 {
		riskText = "HIGH"
		riskColor = &props.Color{Red: 255, Green: 140, Blue: 0}
	} else if riskScore > 1 {
		riskText = "MEDIUM"
		riskColor = &props.Color{Red: 200, Green: 200, Blue: 0}
	}

	m.AddRows(row.New(15).Add(
		col.New(8).Add(
			text.New("EXECUTIVE SUMMARY", props.Text{Size: 16, Style: fontstyle.Bold, Color: headerColor}),
		),
		col.New(4).Add(
			text.New(fmt.Sprintf("RISK RATING: %s", riskText), props.Text{
				Size:  12,
				Style: fontstyle.Bold,
				Align: align.Right,
				Color: riskColor,
			}),
		),
	))

	m.AddRows(row.New(5).Add(col.New(12).Add(text.New(strings.Repeat("-", 100), props.Text{Size: 8, Color: &props.Color{Red: 200, Green: 200, Blue: 200}}))))

	m.AddRows(row.New(8).Add(
		col.New(6).Add(text.New(fmt.Sprintf("Target URL: %s", data.TargetURL), props.Text{Style: fontstyle.Bold})),
		col.New(6).Add(text.New(fmt.Sprintf("Discovery Count: %d", data.TotalHits), props.Text{Align: align.Right})),
	))
	m.AddRows(row.New(8).Add(
		col.New(6).Add(text.New(fmt.Sprintf("Technologies Detected: %d", len(data.Technologies)))),
		col.New(6).Add(text.New(fmt.Sprintf("Total Rounds: %d", data.Rounds), props.Text{Align: align.Right})),
	))

	if len(data.Technologies) > 0 {
		m.AddRows(row.New(20))
		m.AddRows(row.New(15).Add(
			col.New(12).Add(
				text.New("TECHNOLOGY STACK & VULNERABILITIES", props.Text{Size: 14, Style: fontstyle.Bold, Color: headerColor}),
			),
		))

		seen := make(map[string]bool)
		for _, tech := range data.Technologies {
			key := tech.Name + tech.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			ver := tech.Version
			if ver == "" {
				ver = "Unknown"
			}

			m.AddRows(row.New(10).Add(
				col.New(12).Add(
					text.New(fmt.Sprintf("• %s (%s) - v%s", tech.Name, tech.Category, ver), props.Text{Style: fontstyle.Bold, Size: 11}),
				),
			).WithStyle(&props.Cell{BackgroundColor: &props.Color{Red: 245, Green: 245, Blue: 245}}))

			if len(tech.CVEs) == 0 {
				m.AddRows(row.New(8).Add(col.New(12).Add(text.New("  No known high/critical vulnerabilities found.", props.Text{Size: 9, Style: fontstyle.Italic}))))
			}

			for _, cve := range tech.CVEs {
				m.AddRows(row.New(12).Add(
					col.New(3).Add(text.New(cve.ID, props.Text{Size: 9, Style: fontstyle.Bold, Color: dangerColor})),
					col.New(2).Add(text.New(cve.Severity, props.Text{Size: 8})),
					col.New(7).Add(text.New(cve.Description, props.Text{Size: 8})),
				))
			}
			m.AddRows(row.New(5))
		}
	}

	if len(data.Anomalies) > 0 {
		m.AddRows(row.New(20))
		m.AddRows(row.New(15).Add(
			col.New(12).Add(
				text.New("CRITICAL ANOMALIES & FINDINGS", props.Text{Size: 14, Style: fontstyle.Bold, Color: dangerColor}),
			),
		))

		for _, a := range data.Anomalies {
			m.AddRows(row.New(10).Add(
				col.New(4).Add(text.New(a.Path, props.Text{Style: fontstyle.Bold, Color: dangerColor})),
				col.New(8).Add(text.New(a.Reason, props.Text{Size: 10})),
			))
		}
	}

	m.AddRows(row.New(25))
	m.AddRows(row.New(15).Add(
		col.New(12).Add(
			text.New("DISCOVERY LOG", props.Text{Size: 14, Style: fontstyle.Bold, Color: headerColor}),
		),
	))

	m.AddRows(row.New(10).Add(
		col.New(2).Add(text.New("STATUS", props.Text{Style: fontstyle.Bold, Size: 10})),
		col.New(8).Add(text.New("RESOURCE PATH", props.Text{Style: fontstyle.Bold, Size: 10})),
		col.New(2).Add(text.New("SIZE", props.Text{Style: fontstyle.Bold, Size: 10, Align: align.Right})),
	).WithStyle(&props.Cell{BackgroundColor: headerColor, BorderType: border.Full}))

	for i, h := range data.Hits {
		status := 0
		if h.StatusCode != nil {
			status = *h.StatusCode
		}
		size := int64(0)
		if h.Size != nil {
			size = *h.Size
		}

		bgColor := white
		if i%2 == 0 {
			bgColor = &props.Color{Red: 240, Green: 240, Blue: 255}
		}

		m.AddRows(row.New(8).Add(
			col.New(2).Add(text.New(fmt.Sprintf("%d", status), props.Text{Size: 9})),
			col.New(8).Add(text.New(h.Path, props.Text{Size: 9})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", size), props.Text{Size: 9, Align: align.Right})),
		).WithStyle(&props.Cell{BackgroundColor: bgColor}))
	}

	m.AddRows(row.New(30))
	m.RegisterFooter(row.New(15).Add(
		col.New(12).Add(text.New("Confidential - Generated by OBSCURA RECON", props.Text{
			Size:  8,
			Align: align.Center,
			Color: accentColor,
		})),
	))

	doc, err := m.Generate()
	if err != nil {
		return err
	}

	return doc.Save(outputPath)
}

func calculateRisk(data Data) int {
	score := 0
	for _, t := range data.Technologies {
		score += len(t.CVEs)
	}
	score += len(data.Anomalies) * 2
	return score
}
