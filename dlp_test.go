package dhpals

import (
	"crypto/rand"
	"math/big"
	"testing"
)

type bsgsTest struct {
	g, p string
}

var bsgsMassTests = []bsgsTest{
	{"2", "374221219387"},
	{"3", "1419857"},
	{"19", "508389803902"},
}

func TestBSGS(t *testing.T) {
	for i, r := range bsgsMassTests {
		p, _ := new(big.Int).SetString(r.p, 10)
		g, _ := new(big.Int).SetString(r.g, 10)
		totient := phi(p)
		for j := 0; j < 10; j++ {
			x, _ := rand.Int(rand.Reader, totient)
			y := new(big.Int).Exp(g, x, p)
			xx, _ := bsgs(g, y, p)
			if xx.Cmp(x) != 0 {
				t.Fatalf("%s - #%d: BSGS: g = %d, n = %n, want %d, got %d", t.Name(), i, g, p, x, xx)
			}
		}
	}
}

type bsgsPointTest struct {
	g, p, x, y string
}

var bsgsPointTests = []bsgsPointTest{
	{"2", "5", "1", "2"},
	{"3", "17", "14", "2"},
	{"3", "113", "100", "57"},
	{"2", "383", "110", "228"},
	{"71", "251", "197", "210"},
	{"2", "3845246837", "411947586", "1307693885"},
}

func TestPointBSGS(t *testing.T) {
	for i, r := range bsgsPointTests {
		p, _ := new(big.Int).SetString(r.p, 10)
		g, _ := new(big.Int).SetString(r.g, 10)
		x, _ := new(big.Int).SetString(r.x, 10)
		y, _ := new(big.Int).SetString(r.y, 10)

		xx, _ := bsgs(g, y, p)
		if xx.Cmp(x) != 0 {
			t.Fatalf("%s - #%d: BSGS: g = %d, n = %d, y = %d: want %d, got %d", t.Name(), i, g, p, y, x, xx)
		}
	}
}

func BenchmarkBSGS(b *testing.B) {
	// run the BSGS function b.N times
	for n := 0; n < b.N; n++ {
		for _, r := range bsgsPointTests {
			p, _ := new(big.Int).SetString(r.p, 10)
			g, _ := new(big.Int).SetString(r.g, 10)
			y, _ := new(big.Int).SetString(r.y, 10)
			_, _ = bsgs(g, y, p)
		}
	}
}

func BenchmarkES(b *testing.B) {
	// run the ES function b.N times
	for n := 0; n < b.N; n++ {
		for _, r := range bsgsPointTests {
			p, _ := new(big.Int).SetString(r.p, 10)
			g, _ := new(big.Int).SetString(r.g, 10)
			y, _ := new(big.Int).SetString(r.y, 10)
			_ = es(g, y, p)
		}
	}
}

type divideTest struct {
	x, y string
	res  bool
}

var divideTests = []divideTest{
	{"3", "6", true},
	{"45", "56", false},
	{"435345", "374221219387", false},
	{"234234", "328024856392347708811409115924", true},
}

func TestDivide(t *testing.T) {
	for i, r := range divideTests {
		x, _ := new(big.Int).SetString(r.x, 10)
		y, _ := new(big.Int).SetString(r.y, 10)
		res := r.res

		div := divides(x, y)
		if div != res {
			t.Errorf("%s - #%d: divides(%d, %d)", t.Name(), i, x, y)
		}
	}
}

type phiTest struct {
	n, v string
}

var phiTests = []phiTest{
	{"7", "6"},
	{"11", "10"},
	{"374221219387", "374221219386"},
	{"1419857", "1336336"},
	{"303238549752516", "78731307035136"},
}

func TestPhi(t *testing.T) {
	for i, r := range phiTests {
		n, _ := new(big.Int).SetString(r.n, 10)
		v, _ := new(big.Int).SetString(r.v, 10)

		vv := phi(n)
		if vv.Cmp(v) != 0 {
			t.Errorf("%s - #%d: phi(%d): got %d, want %d", t.Name(), i, n, vv, v)
		}
	}
}

type basicPGPointTest struct {
	g, x, y, n, p, pf, ef string
}

var basicPGPointTests = []basicPGPointTest{
	{"71", "72", "210", "250", "251", "5", "3"},
}

func TestBasicPohligHellman(t *testing.T) {
	for i, r := range basicPGPointTests {
		n, _ := new(big.Int).SetString(r.n, 10)
		p, _ := new(big.Int).SetString(r.p, 10)
		g, _ := new(big.Int).SetString(r.g, 10)
		x, _ := new(big.Int).SetString(r.x, 10)
		y, _ := new(big.Int).SetString(r.y, 10)
		ef, _ := new(big.Int).SetString(r.ef, 10)
		pf, _ := new(big.Int).SetString(r.pf, 10)

		x1 := basicPohligHellman(g, y, n, p, pf, ef)
		if x1.Cmp(x) != 0 {
			t.Fatalf("%s - #%d: basic Pollig-Hellman: g = %d, n = %n, want %d, got %d", t.Name(), i, g, n, x, x1)
		}
	}
}

type PGPointTest struct {
	g, p, x, y string
}

var PGPointTests = []PGPointTest{
	{"71", "251", "197", "210"},
	{"2", "3845246837", "411947586", "1307693885"},
	{"6", "171888743238061", "89158850071897", "55876339080020"},
}

func TestPohligHellman(t *testing.T) {
	for i, r := range PGPointTests {
		p, _ := new(big.Int).SetString(r.p, 10)
		g, _ := new(big.Int).SetString(r.g, 10)
		y, _ := new(big.Int).SetString(r.y, 10)
		x, _ := new(big.Int).SetString(r.x, 10)

		x1 := pohligHellman(g, y, p)
		if x1.Cmp(x) != 0 {
			t.Fatalf("%s - #%d: basic Pollig-Hellman: g = %d, n = %n, want %d, got %d", t.Name(), i, g, p, x, x1)
		}
	}
}
