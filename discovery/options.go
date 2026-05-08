package discovery

type ExpandOptions struct {
	IncludeParents bool

	VersionRadius int

	BumpNumericSegments bool

	NumericRadius int

	MaxCandidates int
}

func (o *ExpandOptions) normalize() {
	if o.VersionRadius <= 0 {
		o.VersionRadius = 2
	}
	if o.NumericRadius <= 0 {
		o.NumericRadius = 1
	}
}
