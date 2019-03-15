package cryptopals

import "crypto/aes"

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

func CBCEncrypt(plaintext, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	die(err)

	size := block.BlockSize()
	src := PKCSPadding(plaintext, size)
	dst := make([]byte, len(src))
	last := iv
	for i := 0; i < len(dst); i += size {
		block.Encrypt(dst[i:], XorFixed(src[i:i+size], last))
		last = dst[i : i+size]
	}
	return dst
}

func CBCDecrypt(cipher, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	die(err)

	size := block.BlockSize()
	dst := make([]byte, len(cipher))
	last := iv
	for i := 0; i < len(dst); i += size {
		block.Decrypt(dst[i:], cipher[i:])
		copy(dst[i:], XorFixed(dst[i:i+size], last))
		last = cipher[i : i+size]
	}
	return dst
}
