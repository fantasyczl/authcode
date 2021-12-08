package auth

import "testing"

func TestBin2dec(t *testing.T) {
	params := []struct {
		input string
		exp   int
	}{
		{
			input: "0",
			exp:   0,
		},
		{
			input: "1",
			exp:   1,
		},
		{
			input: "10",
			exp:   2,
		},
		{
			input: "0010",
			exp:   2,
		},
	}

	for _, p := range params {
		r := bin2dec(p.input)
		if r != p.exp {
			t.Fatalf("input: %v, want: %v, got: %v\n", p.input, p.exp, r)
		}
	}
}

func TestStrPadFromLeft(t *testing.T) {
	params := []struct {
		v       int
		length  int
		padding byte
		exp     string
	}{
		{
			v : 1,
			length: 6,
			padding: '0',
			exp : "000001",
		},
		{
			v : 19999,
			length: 6,
			padding: '0',
			exp : "019999",
		},
		{
			v : 199992,
			length: 6,
			padding: '0',
			exp : "199992",
		},
	}

	for _, p := range params {
		r := strPadFromLeft(p.v, p.length, p.padding)
		if r != p.exp {
			t.Fatalf("input: %+v, want: %+v, got: %+v\n", p, p.exp, r)
		}
	}
}
