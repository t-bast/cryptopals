package prng

const (
	w = 32
	n = 624
	m = 397
	r = 31
	f = 1812433253
	a = 0xB5026F5AA96619E9
	u = 29
	d = 0x5555555555555555
	s = 17
	b = 0x71D67FFFEDA60000
	t = 37
	c = 0xFFF7EEE000000000
	l = 43
)

// MT19937 implements the Mersenne Twister with a period of 2^19937 - 1
// (which is a Mersenne prime).
type MT19937 struct {
	mt    []int
	index int
}

// NewMT19937 creates a new random number generator.
func NewMT19937(seed int) *MT19937 {
	mt := make([]int, n)
	mt[0] = seed

	for i := 1; i < n; i++ {
		current := int64(f)*int64(mt[i-1]^(mt[i-1]>>(w-2))) + int64(i)
		mt[i] = int(current % (1 << 32))
	}

	return &MT19937{
		mt:    mt,
		index: n,
	}
}

// NewMT19937FromState creates a new random generator from the given internal
// state.
func NewMT19937FromState(state []int) *MT19937 {
	return &MT19937{
		mt:    state,
		index: 0,
	}
}

// Rand produces a random number.
func (rnd *MT19937) Rand() int {
	if rnd.index >= n {
		rnd.twist()
	}

	y := MT19937Temper(rnd.mt[rnd.index])

	rnd.index++
	return y
}

// twist generates the next n values from the series x_i.
func (rnd *MT19937) twist() {
	lowerMask := (1 << r) - 1
	upperMask := (1 << r)

	for i := 0; i < n; i++ {
		x := (rnd.mt[i] & upperMask) + (rnd.mt[(i+1)%n] & lowerMask)
		xa := x >> 1

		if x%2 != 0 {
			xa = int((uint64(xa) ^ a) % (1 << 32))
		}

		rnd.mt[i] = rnd.mt[(i+m)%n] ^ xa
	}

	rnd.index = 0
}

// MT19937Temper tempers the internal state.
func MT19937Temper(y int) int {
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= int((uint64(y<<t) & c) % (1 << 32))
	y ^= y >> l

	return y
}

// MT19937Untemper reverses MT19937Temper.
func MT19937Untemper(y int) int {
	y ^= y >> l
	y ^= int((uint64(y<<t) & c) % (1 << 32))
	for i := 0; i < 7; i++ {
		y ^= (y << s) & b
	}
	for i := 0; i < 3; i++ {
		y ^= (y >> u) & d
	}

	return y
}
