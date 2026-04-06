package responseanalyze

type Sample struct {
	Key string

	Status int

	Body []byte

	ReportedLength int
}

type Options struct {
	HashBodyPrefixBytes int

	MinSimilarCluster int

	MinDominantCount int

	MaxExampleKeys int
}

func DefaultOptions() Options {
	return Options{
		HashBodyPrefixBytes: 2048,
		MinSimilarCluster:   2,
		MinDominantCount:    5,
		MaxExampleKeys:      5,
	}
}

func (o *Options) normalize() {
	if o.MinSimilarCluster < 2 {
		o.MinSimilarCluster = 2
	}
	if o.MinDominantCount < 2 {
		o.MinDominantCount = 2
	}
	if o.MaxExampleKeys < 0 {
		o.MaxExampleKeys = 0
	}
}

type ClusterSummary struct {
	Pattern string
	Status  int
	BodyLen int
	Count   int

	ExampleKeys []string
}

type Anomaly struct {
	Key     string
	Status  int
	BodyLen int
	Reason  string
}

type Result struct {
	Clusters []ClusterSummary

	SimilarClusters []ClusterSummary

	Anomalies []Anomaly
}
