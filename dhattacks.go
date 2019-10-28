package dhpals

import (
	"math/big"
)

func runDHSmallSubgroupAttack(p, cofactor *big.Int, dh func(*big.Int) []byte) (priv *big.Int) {
	panic("not implemented")
	return
}

// catchKangaroo implements Pollard's kangaroo algorithm.
func catchKangaroo(p, g, y, a, b *big.Int) (m *big.Int, err error) {
	panic("not implemented")
	return
}

func runDHKangarooAttack(p, g, q, cofactor *big.Int, dh func(*big.Int) []byte, getPublicKey func() *big.Int) (priv *big.Int) {
	panic("not implemented")
	return nil
}
