package fingerprint

import (
	"regexp"
)

type Signature struct {
	Name     string
	Category string
	Headers  map[string]*regexp.Regexp
	Body     []*regexp.Regexp
}

var DefaultSignatures = []Signature{

	{
		Name:     "WordPress",
		Category: "CMS",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`WordPress`),
			"Link":         regexp.MustCompile(`wp-json`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`wp-content|wp-includes`),
			regexp.MustCompile(`(?i)<meta name="generator" content="WordPress`),
		},
	},
	{
		Name:     "Drupal",
		Category: "CMS",
		Headers: map[string]*regexp.Regexp{
			"X-Drupal-Cache": regexp.MustCompile(`.*`),
			"X-Generator":    regexp.MustCompile(`Drupal ([\d.]+)`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`Drupal\.settings`),
			regexp.MustCompile(`(?i)<meta name="generator" content="Drupal`),
		},
	},
	{
		Name:     "Joomla",
		Category: "CMS",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<meta name="generator" content="Joomla!`),
			regexp.MustCompile(`scripts/joomla/`),
		},
	},
	{
		Name:     "Magento",
		Category: "CMS / E-Commerce",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`frontend=`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`Mage\.Cookies`),
			regexp.MustCompile(`skin/frontend/`),
		},
	},
	{
		Name:     "Shopify",
		Category: "E-Commerce",
		Headers: map[string]*regexp.Regexp{
			"X-ShopId":        regexp.MustCompile(`.*`),
			"X-Shopify-Stage": regexp.MustCompile(`.*`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.shopify\.com`),
			regexp.MustCompile(`Shopify\.theme`),
		},
	},

	{
		Name:     "React",
		Category: "Framework",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`data-reactroot`),
			regexp.MustCompile(`_reactRootContainer`),
			regexp.MustCompile(`react\.production\.min\.js`),
		},
	},
	{
		Name:     "Vue",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`Vue`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`data-v-`),
			regexp.MustCompile(`__vue__`),
		},
	},
	{
		Name:     "Laravel",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`laravel_session`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`(?i)csrf-token`),
			regexp.MustCompile(`laravel`),
		},
	},
	{
		Name:     "Django",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`csrftoken=`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`__django_`),
		},
	},
	{
		Name:     "Next.js",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`Next\.js`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`/_next/static/`),
			regexp.MustCompile(`(?i)<script id="__NEXT_DATA__"`),
		},
	},

	{
		Name:     "Nginx",
		Category: "Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`nginx(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "Apache",
		Category: "Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Apache(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "LiteSpeed",
		Category: "Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`LiteSpeed`),
		},
	},
	{
		Name:     "IIS",
		Category: "Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Microsoft-IIS/([\d.]+)`),
		},
	},
	{
		Name:     "Cloudflare",
		Category: "Server / CDN / WAF",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`cloudflare`),
			"Cf-Ray": regexp.MustCompile(`.*`),
		},
	},
	{
		Name:     "Akamai",
		Category: "WAF / CDN",
		Headers: map[string]*regexp.Regexp{
			"X-Akamai-Transformed": regexp.MustCompile(`.*`),
			"X-EdgeConnect-Mid":    regexp.MustCompile(`.*`),
		},
	},
	{
		Name:     "Imperva / Incapsula",
		Category: "WAF",
		Headers: map[string]*regexp.Regexp{
			"X-Iinfo":     regexp.MustCompile(`.*`),
			"Set-Cookie":  regexp.MustCompile(`visid_incap`),
		},
	},
	{
		Name:     "AWS WAF",
		Category: "WAF",
		Headers: map[string]*regexp.Regexp{
			"X-Amzn-Trace-Id": regexp.MustCompile(`.*`),
		},
	},
	{
		Name:     "ModSecurity",
		Category: "WAF",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`ModSecurity|NOVIS`),
		},
	},

	{
		Name:     "PHP",
		Category: "Language",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`PHP(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "Ruby on Rails",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`Phusion Passenger`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`assets/application-.*\.js`),
		},
	},

	{
		Name:     "Google Analytics",
		Category: "Analytics",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`google-analytics\.com/analytics\.js`),
			regexp.MustCompile(`googletagmanager\.com/gtag/js`),
		},
	},
}
