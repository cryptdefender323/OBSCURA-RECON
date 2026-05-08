package banner

import (
	"fmt"
	"strings"
)

const Logo = `
   ___  ____  ____  _____ _   _ ____      _    
  / _ \| __ )/ ___|| ____| | | |  _ \    / \   
 | | | |  _ \\___ \|  _| | | | | |_) |  / _ \  
 | |_| | |_) |___) | |___| |_| |  _ <  / ___ \ 
  \___/|____/|____/|_____|\___/|_| \_\/_/   \_\
                                                
  Advanced Web Reconnaissance & Security Assessment
  Multi-Round Discovery | CVE Correlation | Anomaly Detection
`

const Version = "v2.0.0"
const Author = "CryptDefender"

func Print() {
	fmt.Println("\033[1;36m" + Logo + "\033[0m")
	fmt.Printf("\033[1;33m  Version: %s | Author: %s\033[0m\n\n", Version, Author)
}

func PrintStats(target string, rounds int, wordlist string) {
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("  \033[1;32m⚡ Target:\033[0m     %s\n", target)
	fmt.Printf("  \033[1;32m📊 Rounds:\033[0m     %d\n", rounds)
	fmt.Printf("  \033[1;32m📝 Wordlist:\033[0m   %s\n", wordlist)
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
}

func PrintSuccess(message string) {
	fmt.Printf("\033[1;32m[✓]\033[0m %s\n", message)
}

func PrintInfo(message string) {
	fmt.Printf("\033[1;34m[*]\033[0m %s\n", message)
}

func PrintWarning(message string) {
	fmt.Printf("\033[1;33m[!]\033[0m %s\n", message)
}

func PrintError(message string) {
	fmt.Printf("\033[1;31m[✗]\033[0m %s\n", message)
}

func PrintProgress(current, total int, message string) {
	percent := float64(current) / float64(total) * 100
	bar := strings.Repeat("█", int(percent/5))
	spaces := strings.Repeat("░", 20-len(bar))
	fmt.Printf("\r\033[1;36m[%s%s]\033[0m %.0f%% - %s", bar, spaces, percent, message)
	if current == total {
		fmt.Println()
	}
}
