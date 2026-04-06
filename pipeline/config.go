package pipeline

import (
	"obscura/discovery"
	"obscura/reqconfig"
	"obscura/responseanalyze"
	"obscura/wordlistgen"
)

type Config struct {
	TargetURL string

	BaseWordlistPath string

	BaseLines []string

	GobusterPath string

	GobusterExtraArgs []string

	MaxRounds int

	MaxQueueDrain int

	Wordlist  wordlistgen.Config
	Analyze   responseanalyze.Options
	Discovery discovery.ExpandOptions

	SeedFromAnomalies bool

	SeedFromAllHits bool
	ReqConfig       reqconfig.Config

	StatusCodes string

	ExcludeCodes string

	ExcludeLength string

	Wildcard bool
}

func DefaultConfig() Config {
	a := responseanalyze.DefaultOptions()
	a.HashBodyPrefixBytes = 0
	return Config{
		MaxRounds:         3,
		MaxQueueDrain:     64,
		Wordlist:          wordlistgen.DefaultConfig(),
		Analyze:           a,
		Discovery:         discovery.ExpandOptions{},
		SeedFromAnomalies: true,
		SeedFromAllHits:   false,
	}
}

func (c *Config) normalize() {
	if c.MaxRounds <= 0 {
		c.MaxRounds = 3
	}
	if c.MaxQueueDrain <= 0 {
		c.MaxQueueDrain = 64
	}
}
