package cryptopals

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"math/bits"
	"os"
)

func die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	die(err)
	return b
}

func HexToBase64(s string) string {
	return base64.StdEncoding.EncodeToString(mustHexDecode(s))
}

func XorFixed(a, b []byte) []byte {
	if len(a) != len(b) {
		log.Fatalf("len a (%d) != len b (%d)", len(a), len(b))
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

type FrequencyMap [1 << 8]float64

func NewFrequencyMap(b []byte) *FrequencyMap {
	var freqs FrequencyMap
	for _, c := range b {
		freqs[c]++
	}
	for c := range freqs {
		freqs[c] /= float64(len(b))
	}
	return &freqs
}

// Distance returns the Pythagorean vector distance of two FrequencyMaps.
func (f *FrequencyMap) Distance(other *FrequencyMap) float64 {
	// compare maps, compute n-dimensional vector length
	var sum float64
	for i := 0; i < 1<<8; i++ {
		distance := f[byte(i)] - other[byte(i)]
		distance *= distance
		sum += distance
	}
	return math.Sqrt(sum)
}

// Similarity returns the inverse of Distance.
// 1 is maximally alike and 0 is minimally alike.
func (f *FrequencyMap) Similarity(b []byte) float64 {
	return 1 - f.Distance(NewFrequencyMap(b))
}

var EnglishFreqs *FrequencyMap

func SaveFrequencyMap() {
	b, err := ioutil.ReadFile("moby-dick.txt")
	die(err)

	EnglishFreqs = NewFrequencyMap(b)

	f, err := os.Create("freq.gob")
	die(err)
	defer f.Close()
	enc := gob.NewEncoder(f)
	err = enc.Encode(EnglishFreqs)
	die(err)
}

func LoadFrequencyMap() {
	f, err := os.Open("freq.gob")
	die(err)
	defer f.Close()
	dec := gob.NewDecoder(f)
	err = dec.Decode(&EnglishFreqs)
	die(err)
}

func init() {
	// SaveFrequencyMap()
	LoadFrequencyMap()
}

// Bayesian Englishness converges on 1 too quickly!
func BayesianEnglishness(b []byte) float64 {
	// Bayesian formula:
	// P(E|C) = P(C|E) x P(E) ÷ (P(C|E) x P(E) + P(C|~E) x P(~E))

	// product(freq[c] for c in b) / (product + base odds)
	probability := .5
	const pChar float64 = 1.0 / (1 << 8)

	for _, c := range b {
		freq := EnglishFreqs[c]
		if freq == 0 && c < 1<<7 {
			continue
		}
		inverse := (1 - probability)
		temp := freq * probability
		probability = temp / (temp + pChar*inverse)
	}
	return probability
}

func Englishness(b []byte) (float64, bool) {
	englishness := EnglishFreqs.Similarity(b)
	return englishness, englishness > 0.6
}

func XorByte(b []byte, key byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[i] ^ key
	}
	return result
}

func MostEnglishXor(b []byte) (key byte, score float64, decoded string) {
	for i := 0; i < 1<<8; i++ {
		trial := XorByte(b, byte(i))
		englishness := EnglishFreqs.Similarity(trial)
		if englishness > score {
			score = englishness
			key = byte(i)
		}
	}
	decoded = string(XorByte(b, key))
	return
}

func mustHexDecodeFile(name string) (lines [][]byte) {
	f, err := os.Open(name)
	die(err)
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		b, err := hex.DecodeString(s.Text())
		die(err)
		lines = append(lines, b)
	}
	die(s.Err())
	return
}

func MostDecodableLine(filename string) string {
	lines := mustHexDecodeFile(filename)
	englishness, result := 0.0, ""
	for _, line := range lines {
		_, score, decoded := MostEnglishXor(line)
		if score > englishness {
			englishness, result = score, decoded
		}
	}
	return result
}

func XorRepeating(base, key []byte) []byte {
	result := make([]byte, len(base))
	for i := range base {
		result[i] = base[i] ^ key[i%len(key)]
	}
	return result
}

func HammingDistance(a, b []byte) int {
	sum := 0
	for _, c := range XorFixed(a, b) {
		sum += bits.OnesCount8(c)
	}
	return sum
}

func mustBase64DecodeFile(name string) []byte {
	b, err := ioutil.ReadFile(name)
	die(err)
	b, err = base64.StdEncoding.DecodeString(string(b))
	die(err)
	return b
}

func AverageHammingDistanceForSize(contents []byte, size int) float64 {
	sum, loops := 0, 0.0
	for i := 0; i < len(contents)-size; i += size {
		a, b := contents[i:i+size], contents[i+size:i+size+size]
		sum += HammingDistance(a, b)
		loops++ // lol, too lazy to do the math
	}
	return float64(sum) / loops / float64(size)
}

func Transpose(contents []byte, size int) [][]byte {
	result := make([][]byte, size)
	for i := 0; i < size; i++ {
		result[i] = make([]byte, 0, len(contents)%size)
		for j := i; j < len(contents); j += size {
			result[i] = append(result[i], contents[j])
		}
	}
	return result
}

func GuessXorRepeating(contents []byte, maxSize int) (key []byte, decoded string) {
	bestSize := 2
	lowestAvg := AverageHammingDistanceForSize(contents, bestSize)
	for keysize := 3; keysize < maxSize; keysize++ {
		avg := AverageHammingDistanceForSize(contents, keysize)
		if avg < lowestAvg {
			bestSize = keysize
			lowestAvg = avg
		}
	}
	for _, block := range Transpose(contents, bestSize) {
		subkey, _, _ := MostEnglishXor(block)
		key = append(key, subkey)
	}
	decoded = string(XorRepeating(contents, key))
	return
}

func AESDecrypt(cipher, key []byte) []byte {
	block, err := aes.NewCipher(key)
	die(err)
	dst := make([]byte, len(cipher))
	for i := 0; i < len(dst); i += block.BlockSize() {
		block.Decrypt(dst[i:], cipher[i:])
	}
	return dst
}
