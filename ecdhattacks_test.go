package dhpals

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/dnkolegov/dhpals/elliptic"
	"github.com/dnkolegov/dhpals/x128"
)

func TestECDHInvalidCurveAttack(t *testing.T) {
	p128 := elliptic.P128()

	basePointOrder, _ := new(big.Int).SetString("29246302889428143187362802287225875743", 10)
	ex, ey := p128.ScalarBaseMult(basePointOrder.Bytes())

	if fmt.Sprintf("%d", ex) != "0" || fmt.Sprintf("%d", ey) != "0" {
		t.Fatalf("%s: correction test failed", t.Name())
	}

	// Alice generates a key pair.
	aPriv, ax, ay, _ := elliptic.GenerateKey(p128, nil)
	// Bob generates a key pair.
	bPriv, bx, by, _ := elliptic.GenerateKey(p128, nil)

	// Alice runs DH.
	asx, asy := p128.ScalarMult(bx, by, aPriv)
	// Bob runs DH.
	bsx, bsy := p128.ScalarMult(ax, ay, bPriv)

	if asx.Cmp(bsx) != 0 || asy.Cmp(bsy) != 0 {
		t.Errorf("%s: incorrect ECDH", t.Name())
	}

	oracle, isKeyCorrect, _ := newECDHAttackOracle(p128)

	privateKey := runECDHInvalidCurveAttack(oracle)
	t.Logf("%s: Private key:%d", t.Name(), privateKey)

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatalf("%s: wrong private key was found in the invalid curve attack", t.Name())
	}
}

func TestECDHSmallSubgroupAttack(t *testing.T) {
	p48 := elliptic.P48()

	if !p48.IsOnCurve(p48.Params().Gx, p48.Params().Gy) {
		t.Fatalf("%s: p48: base point is not on the curve", t.Name())
	}

	basePointOrder := p48.Params().N
	ex, ey := p48.ScalarBaseMult(basePointOrder.Bytes())

	if fmt.Sprintf("%d", ex) != "0" || fmt.Sprintf("%d", ey) != "0" {
		t.Fatalf("%s: sanity check failed", t.Name())
	}

	oracle, isKeyCorrect, _ := newECDHAttackOracle(p48)

	privateKey := runECDHSmallSubgroupAttack(p48, oracle)

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatalf("%s: wrong private key was found in the small-sugbroup attack on ECDH", t.Name())
	}
}

func TestCurvesP128AndX128(t *testing.T) {
	p128 := elliptic.P128()

	for i := 0; i < 1000; i++ {
		k, _ := rand.Int(rand.Reader, p128.Params().P)
		kx, ky := p128.ScalarBaseMult(k.Bytes())

		if !p128.IsOnCurve(kx, ky) {
			t.Fatalf("%s: the point is not on the p128 curve", t.Name())
		}

		// u = x - 178
		// v = y
		ku := x128.ScalarBaseMult(k.Bytes())
		kv := new(big.Int).Set(ky)

		if !x128.IsOnCurve(ku, kv) {
			t.Fatalf("%s: the point is not on the x128 curve", t.Name())
		}

		if new(big.Int).Sub(kx, big.NewInt(178)).Cmp(ku) != 0 {
			t.Errorf("%s: comparison failed on (%d, %d, %d)", t.Name(), k, ku, kx)
		}
	}
}

type ecKangarooTest struct {
	k, b string
}

var ecKangarooTests = []ecKangarooTest{
	{"10", "100"},
	{"12130", "17000"},
	{"12132880", "22132880"},
}

func TestECKangarooAlgorithm(t *testing.T) {
	curve := elliptic.P128()
	a := new(big.Int).Set(Big0)
	bx, by := curve.Params().Gx, curve.Params().Gy
	for _, e := range ecKangarooTests {
		k, _ := new(big.Int).SetString(e.k, 10)
		b, _ := new(big.Int).SetString(e.b, 10)

		x, y := curve.ScalarBaseMult(k.Bytes())
		kk, err := catchKangarooOnCurve(curve, bx, by, x, y, a, b)
		if err != nil {
			t.Fatalf("%s: %s", t.Name(), err)
		}
		if kk.Cmp(k) != 0 {
			t.Fatalf("%s: (%d, %d) failed", t.Name(), k, b)
		}
	}
}

func TestTwistAttack(t *testing.T) {
	v, _ := new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	u := new(big.Int).SetInt64(4)

	if !x128.IsOnCurve(u, v) {
		t.Fatalf("%s: the point is not on the x128 curve", t.Name())
	}

	ecdh, isKeyCorrect, getPublic, vulnOracle := newX128TwistAttackOracle()

	privateKey := runECDHTwistAttack(ecdh, getPublic, vulnOracle)

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatalf("%s: wrong private key was found in the sugbroup attack", t.Name())
	}

	fmt.Print(privateKey)
}
