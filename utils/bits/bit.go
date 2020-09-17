package bits

func SetBit8(n uint8, pos uint8) uint8 {
	n |= (1 << pos)
	return n
}

func ClearBit8(n uint8, pos uint8) uint8 {
	n &= ^(1 << pos)
	return n
}

func HasBit8(n uint8, pos uint8) bool {
	val := n & (1 << pos)
	return (val > 0)
}
