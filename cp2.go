package cryptopals

func PKCSPadding(b []byte, padding int) []byte {
	remainder := len(b) % padding
	if remainder == 0 {
		return b
	}
	padby := padding - remainder
	r := make([]byte, len(b)+padby)
	copy(r, b)
	for i := 0; i < padby; i++ {
		r[len(r)-1-i] = '\x04'
	}
	return r
}
