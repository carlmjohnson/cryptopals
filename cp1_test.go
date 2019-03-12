package cryptopals

import (
	"bytes"
	"testing"
)

func equalString(t *testing.T, have, expect string) {
	t.Helper()
	if have != expect {
		t.Errorf("got %q; want %q", have, expect)
	}
}

func equalBytes(t *testing.T, have, expect []byte) {
	t.Helper()
	if string(have) != string(expect) {
		t.Errorf("got \"% x\"\nwant \"% x\"", have, expect)
	}
}

func Test1(t *testing.T) {
	tcs := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "",
			input:  "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			output: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			equalString(t, HexToBase64(tc.input), tc.output)
		})
	}
}

func Test2(t *testing.T) {
	tcs := []struct {
		name           string
		inputa, inputb string
		output         string
	}{
		{
			name:   "",
			inputa: "1c0111001f010100061a024b53535009181c",
			inputb: "686974207468652062756c6c277320657965",
			output: "746865206b696420646f6e277420706c6179",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var (
				inputa = mustHexDecode(tc.inputa)
				inputb = mustHexDecode(tc.inputb)
				output = mustHexDecode(tc.output)
			)
			result := XorFixed(inputa, inputb)
			equalBytes(t, result, output)
		})
	}
}

func Test3a(t *testing.T) {
	tcs := []struct {
		name   string
		input  string
		output bool
	}{
		{
			name:   "hex junk",
			input:  "1c0111001f010100061a024b53535009181c",
			output: false,
		},
		{
			name:   "ishmael",
			input:  "call me ishmael",
			output: true,
		},
		{
			name:   "rap",
			input:  "Cooking MC's like a pound of bacon",
			output: true,
		},
		{
			name:   "line noise",
			input:  "\x00\x11\x22\x33",
			output: false,
		},
		{
			name:   "Japanese",
			input:  "日本語",
			output: false,
		},
		{
			name:   "world",
			input:  "HELLO, WORLD!",
			output: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			englishness, ok := Englishness([]byte(tc.input))
			if ok != tc.output {
				t.Errorf("Englishness of %q = %.2f", tc.input, englishness)
			}
		})
	}
}
func Test3b(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		decoded string
		key     byte
	}{
		{
			name:    "",
			input:   "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
			decoded: "Cooking MC's like a pound of bacon",
			key:     0x58,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			input := mustHexDecode(tc.input)
			key, _, decoded := MostEnglishXor(input)
			equalString(t, decoded, tc.decoded)
			if key != tc.key {
				t.Errorf("bad key: %0x != %0x", key, tc.key)
			}
		})
	}
}

func Test4(t *testing.T) {
	tcs := []struct {
		name     string
		filename string
		output   string
	}{
		{
			name:     "",
			filename: "4.txt",
			output:   "Now that the party is jumping\n",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			equalString(t, MostDecodableLine(tc.filename), tc.output)
		})
	}
}

func Test5(t *testing.T) {
	tcs := []struct {
		name       string
		input, key string
		output     string
	}{
		{
			name:   "vanilla",
			input:  "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			key:    "ICE",
			output: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			result := XorRepeating([]byte(tc.input), []byte(tc.key))
			equalBytes(t, result, mustHexDecode(tc.output))
		})
	}
}

func Test6a(t *testing.T) {
	tcs := []struct {
		name  string
		a, b  string
		count int
	}{
		{
			name:  "fozzie",
			a:     "this is a test",
			b:     "wokka wokka!!!",
			count: 37,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := HammingDistance([]byte(tc.a), []byte(tc.b))
			if got != tc.count {
				t.Errorf("bad hamming distance %d != %d", got, tc.count)
			}
		})
	}
}

func Test6b(t *testing.T) {
	tcs := []struct {
		name       string
		input      string
		size       int
		transposed string
	}{
		{
			name:       "abc",
			input:      "abcabcabca",
			size:       3,
			transposed: "aaaabbbccc",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			transposed := Transpose([]byte(tc.input), tc.size)
			joined := bytes.Join(transposed, []byte(""))
			equalString(t, string(joined), tc.transposed)
		})
	}
}

func Test6c(t *testing.T) {
	tcs := []struct {
		name     string
		filename string
		key      string
		decoded  string
	}{
		{
			name:     "Vigenere",
			filename: "6.txt",
			key:      "5465726d696e61746f7220583a204272696e6720746865206e6f697365",
			decoded:  "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			contents := mustBase64DecodeFile(tc.filename)
			key, decoded := GuessXorRepeating(contents, 40)
			equalString(t, decoded, tc.decoded)
			equalBytes(t, key, mustHexDecode(tc.key))
		})
	}
}
