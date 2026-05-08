package gobusterexec_test

import (
	"encoding/json"
	"fmt"

	"obscura/gobusterexec"
)

func ExampleParseLine() {
	line := "/admin (Status: 302) [Size: 123]"
	h, ok := gobusterexec.ParseLine(gobusterexec.ModeDir, line)
	if !ok {
		return
	}
	b, _ := json.Marshal(h)
	fmt.Println(string(b))

}
