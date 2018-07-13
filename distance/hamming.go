package distance

// Hamming returns the hamming distance of two strings.
// Highly inefficient implementation but simple enough.
func Hamming(s1, s2 string) int {
	minLen := len(s1)
	if len(s2) < len(s1) {
		minLen = len(s2)
	}

	d := 0
	for i := 0; i < minLen; i++ {
		b1 := s1[i]
		b2 := s2[i]

		for j := uint(0); j < 8; j++ {
			bb1 := b1 >> j
			bb2 := b2 >> j

			if (bb1 & 1) != (bb2 & 1) {
				d++
			}
		}

	}

	return d
}
