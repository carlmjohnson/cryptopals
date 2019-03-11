package cryptopals

import (
	"bufio"
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

var englishCharFreqs = map[byte]float64{}

func MakeFrequencies() {
	b, err := ioutil.ReadFile("moby-dick.txt")
	die(err)
	letterCount := float64(0)
	for _, c := range b {
		letterCount++
		englishCharFreqs[c]++
	}
	for c, f := range englishCharFreqs {
		englishCharFreqs[c] = f / letterCount
	}
	f, err := os.Create("freq.gob")
	die(err)
	defer f.Close()
	enc := gob.NewEncoder(f)
	err = enc.Encode(englishCharFreqs)
	die(err)
}

func LoadFrequencies() {
	f, err := os.Open("freq.gob")
	die(err)
	defer f.Close()
	dec := gob.NewDecoder(f)
	err = dec.Decode(&englishCharFreqs)
	die(err)
}

func init() {
	// MakeFrequencies()
	LoadFrequencies()
}

// Bayesian Englishness converges on 1 too quickly!
func BayesianEnglishness(b []byte) float64 {
	// Bayesian formula:
	// P(E|C) = P(C|E) x P(E) ÷ (P(C|E) x P(E) + P(C|~E) x P(~E))

	// product(freq[c] for c in b) / (product + base odds)
	probability := .5
	const pChar float64 = 1.0 / (1 << 8)

	for _, c := range b {
		freq, ok := englishCharFreqs[c]
		if !ok && c < 1<<7 {
			continue
		}
		inverse := (1 - probability)
		temp := freq * probability
		probability = temp / (temp + pChar*inverse)
	}
	return probability
}

func Englishness(b []byte) float64 {
	// make char frequency map
	freqs := make([]float64, 1<<8)
	for _, c := range b {
		freqs[c]++
	}
	for c := range freqs {
		freqs[c] /= float64(len(b))
	}

	// compare maps, compute n-dimensional vector length
	var sum float64
	for i := 0; i < 1<<8; i++ {
		distance := englishCharFreqs[byte(i)] - freqs[byte(i)]
		distance *= distance
		sum += distance
	}
	// subtract the square root, so 1 is maximally alike, 0 is minimally alike
	return 1 - math.Sqrt(sum)
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
		englishness := Englishness(trial)
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
	// fixme
	// fmt.Println("size:", bestSize)
	for _, block := range Transpose(contents, bestSize) {
		subkey, _, _ := MostEnglishXor(block)
		// fixme
		// fmt.Printf("block %v\n", score == 1.0)
		key = append(key, subkey)
	}
	decoded = string(XorRepeating(contents, key))
	return
}
