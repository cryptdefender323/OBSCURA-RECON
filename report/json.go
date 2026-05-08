package report

import (
	"encoding/json"
	"os"
)

func GenerateJSON(outputPath string, data Data) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
