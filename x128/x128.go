// Package x128 implements the insecure Montgomery curve x128 defined in the Cryptopals challenge 60.
package x128

import (
	"crypto/rand"
	"io"
	"math/big"
)

var (
	// A  - the a parameter.
	A = big.NewInt(534)
	// N - the order of the base point.
	N, _ = new(big.Int).SetString("233970423115425145498902418297807005944", 10)
	// P - the order of the underlying field.
	P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	// Q - the order of the subgroup.
	Q, _ = new(big.Int).SetString("29246302889428143187362802287225875743", 10)
	// U - the base point coordinate.
	U = big.NewInt(4)
	// V - the base point coordinate.
	V, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func ScalarBaseMult(k []byte) *big.Int {
	return ScalarMult(U, k)
}

func ScalarMult(in *big.Int, k []byte) *big.Int {
	return ladder(in, new(big.Int).SetBytes(k))
}

func IsOnCurve(u, v *big.Int) bool {
	panic("not implemented")
	return false
}

func cswap(x, y *big.Int, b bool) (u, v *big.Int) {
	panic("not implemented")
	return nil, nil
}

func ladder(u, k *big.Int) *big.Int {
	panic("not implemented")
	return nil
}

func GenerateKey(rng io.Reader) (priv []byte, pub *big.Int, err error) {
	if rng == nil {
		rng = rand.Reader
	}

	bitSize := Q.BitLen()
	byteLen := (bitSize + 7) >> 3
	priv = make([]byte, byteLen)

	for pub == nil {
		_, err = io.ReadFull(rng, priv)
		if err != nil {
			return
		}
		if new(big.Int).SetBytes(priv).Cmp(Q) >= 0 {
			continue
		}

		pub = ScalarBaseMult(priv)
	}
	return
}
