package responseanalyze

func effectiveBodyLen(s Sample) int {
	if len(s.Body) > 0 {
		return len(s.Body)
	}
	if s.ReportedLength > 0 {
		return s.ReportedLength
	}
	return 0
}
