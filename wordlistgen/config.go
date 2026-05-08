package wordlistgen

type Config struct {
	MinTokenLen int

	MaxTokenLen int

	MaxResponseBytes int

	Suffixes []string

	Prefixes []string

	DedupeCaseFold bool

	WAFBypassLevel int
}

func DefaultConfig() Config {
	return Config{
		MinTokenLen:      3,
		MaxTokenLen:      48,
		MaxResponseBytes: 2 << 20,
		Suffixes: []string{
			"dev", "test", "staging", "stage", "prod", "local",
			"old", "new", "backup", "bak", "internal", "int",
		},
		Prefixes: []string{
			"dev", "test", "staging", "prod", "internal",
		},
		DedupeCaseFold: true,
	}
}

func (c *Config) normalize() {
	if c.MinTokenLen < 1 {
		c.MinTokenLen = 3
	}
	if c.MaxTokenLen < c.MinTokenLen {
		c.MaxTokenLen = 48
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = 2 << 20
	}
}
