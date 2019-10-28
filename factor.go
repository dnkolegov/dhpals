package dhpals

import (
	"math"
	"math/big"

	"github.com/ghhenry/intfact"
)

type factor struct {
	fact *big.Int
	exp  int64
}

// factorize factorizes an input number using a trivial algorithm and returns factors with theirs exponents.
// The factors must be less than 2^32.
func factorize(n *big.Int) []factor {
	factors := make([]factor, 0)
	l := intfact.NewFactors(n)
	l.TrialDivision(math.MaxUint32)
	for p := l.First; p != nil; p = p.Next {
		factors = append(factors, factor{
			p.Fac, int64(p.Exp),
		})
	}
	return factors
}
