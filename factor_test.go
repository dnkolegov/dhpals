package dhpals

import (
	"math/big"
	"testing"
)

type factorizationTest struct {
	n       string
	factors []factor
}

var factorizationTests = []factorizationTest{
	{
		"30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570",
		[]factor{
			{big.NewInt(2), 1},
			{big.NewInt(3), 2},
			{big.NewInt(5), 1},
			{big.NewInt(109), 1},
			{big.NewInt(7963), 1},
			{big.NewInt(8539), 1},
			{big.NewInt(20641), 1},
			{big.NewInt(38833), 1},
			{big.NewInt(39341), 1},
			{big.NewInt(46337), 1},
			{big.NewInt(51977), 1},
			{big.NewInt(54319), 1},
			{big.NewInt(57529), 1},
			{big.NewInt(96142199), 1},
		},
	},
}

func TestFactorization(t *testing.T) {
	for i, r := range factorizationTests {
		n, _ := new(big.Int).SetString(r.n, 10)
		wantedFactors := r.factors
		gotFactors := factorize(n)
		for j := 0; j < len(wantedFactors); j++ {
			if gotFactors[j].fact.Cmp(wantedFactors[j].fact) != 0 || gotFactors[j].exp != wantedFactors[j].exp {
				t.Fatalf("%s - #%d: factorize(%d)", t.Name(), i, n)
			}
		}
	}
}
