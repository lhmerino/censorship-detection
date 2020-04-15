package bits

func SetBit(n int, pos uint) int {
	n |= (1 << pos)
	return n
}

func ClearBit(n int, pos uint) int {
	mask := ^(1 << pos)
	n &= mask
	return n
}

func HasBit(n int, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}
