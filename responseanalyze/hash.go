package responseanalyze

import "hash/fnv"

func prefixHash64(b []byte, n int) uint64 {
	if n <= 0 || len(b) == 0 {
		return 0
	}
	if len(b) > n {
		b = b[:n]
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}
