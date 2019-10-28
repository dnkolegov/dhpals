package dhpals

import (
	"math/big"

	"github.com/dnkolegov/dhpals/elliptic"
	"github.com/dnkolegov/dhpals/x128"
)

func runECDHInvalidCurveAttack(ecdh func(x, y *big.Int) []byte) (priv *big.Int) {
	panic("not implemented")
	return
}

func runECDHSmallSubgroupAttack(curve elliptic.Curve, ecdh func(x, y *big.Int) []byte) (priv *big.Int) {
	panic("not implemented")
	return
}

func runECDHTwistAttack(ecdh func(x *big.Int) []byte, getPublicKey func() (*big.Int, *big.Int), privateKeyOracle func(*big.Int) *big.Int) (priv *big.Int) {
	panic("not implemented")
	return
}

type twistPoint struct {
	order *big.Int
	point *big.Int
}

// findAllPointsOfPrimeOrderOnX128 finds a point with a specified order for u^3 + A*u^2 + u in GF(p).
func findAllPointsOfPrimeOrderOnX128() (points []twistPoint) {
	// It is known, that both curves contain 2*p+2 points: |E| + |T| = 2*p + 2
	panic("not implemented")
	x128.ScalarBaseMult(big.NewInt(1).Bytes())
	return
}

// catchKangarooOnMontgomeryCurve implements Pollard's kangaroo algorithm on a curve.
func catchKangarooOnCurve(curve elliptic.Curve, bx, by, x, y, a, b *big.Int) (m *big.Int, err error) {
	// k is calculated based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
	panic("not implemented")
	return
}
