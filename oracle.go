package dhpals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/dnkolegov/dhpals/dhgroup"
	"github.com/dnkolegov/dhpals/elliptic"
	"github.com/dnkolegov/dhpals/x128"
)

const (
	dhKeyAgreementConst = "crazy flamboyant for the rap enjoyment"
)

func mixKey(k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(dhKeyAgreementConst))
	return mac.Sum(nil)
}

func newDHOracle(id dhgroup.ID) (
	dh func(publicKey *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() *big.Int,
) {

	var dhGroup, _ = dhgroup.GroupForGroupID(id)

	dhKey, _ := dhGroup.GenerateKey(nil)

	dh = func(publicKey *big.Int) []byte {
		sharedKey, err := dhGroup.DH(dhKey.Private, publicKey)
		if err != nil {
			panic(err)
		}
		return mixKey(sharedKey.Bytes())
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(dhKey.Private.Bytes(), key)
	}

	getPublicKey = func() *big.Int {
		return dhKey.Public
	}

	return
}

func newECDHAttackOracle(curve elliptic.Curve) (
	ecdh func(x, y *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (sx, sy *big.Int),
) {

	priv, x, y, err := elliptic.GenerateKey(curve, nil)
	fmt.Printf("Private key:%d\n", new(big.Int).SetBytes(priv))
	if err != nil {
		panic(err)
	}

	ecdh = func(x, y *big.Int) []byte {
		sx, sy := curve.ScalarMult(x, y, priv)
		k := append(sx.Bytes(), sy.Bytes()...)
		return mixKey(k)
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(priv, key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return x, y
	}

	return
}

func newX128TwistAttackOracle() (
	ecdh func(x *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (*big.Int, *big.Int),
	privateKeyOracle func(*big.Int) *big.Int,
) {

	priv, pub, err := x128.GenerateKey(nil)
	fmt.Printf("Private key:%d\n", new(big.Int).SetBytes(priv))
	if err != nil {
		panic(err)
	}

	ecdh = func(x *big.Int) []byte {
		sx := x128.ScalarMult(x, priv)
		return mixKey(sx.Bytes())
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(priv, key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return pub, new(big.Int).SetBytes(priv)
	}

	privateKeyOracle = func(q *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).SetBytes(priv), q)
	}

	return ecdh, isKeyCorrect, getPublicKey, privateKeyOracle
}

// newToxOracle emulates Tox handshake within https://github.com/TokTok/c-toxcore/issues/426.
func newToxOracle(id dhgroup.ID) (
	discovery func(id string, op string, key []byte) ([]byte, error),
	handshake func(name string, payload []byte) ([]byte, error),
	transport func(id string, msg []byte) ([]byte, error),
	isKeyCorrect func([]byte) bool,
	getPrivate func() []byte,
) {
	var dhGroup, _ = dhgroup.GroupForGroupID(id)
	static, _ := dhGroup.GenerateKey(nil)
	var key []byte

	pubKeys := make(map[string][]byte)
	pubKeys["Bob"] = static.Public.Bytes()

	transportKeys := make(map[string][32]byte)

	kem := dhkemScheme{group: dhGroup}

	discovery = func(id string, op string, key []byte) ([]byte, error) {
		if op == "get" {
			pub, ok := pubKeys[id]
			if !ok {
				return nil, errors.New("key discovery: user not found")
			}
			return pub, nil
		} else if op == "set" {
			pubKeys[id] = key
		}
		return nil, nil
	}

	handshake = func(name string, payload []byte) ([]byte, error) {
		peerPublicStatic, err := discovery(name, "get", nil)
		if err != nil {
			panic("unknown peer")
		}

		peerPublicEphemeral := kem.Decap(static.Private, new(big.Int).SetBytes(peerPublicStatic), payload)

		ephemeral, _ := dhGroup.GenerateKey(nil)
		ct := kem.Encap(static.Private, new(big.Int).SetBytes(peerPublicStatic), ephemeral.Public.Bytes())

		key = new(big.Int).Exp(new(big.Int).SetBytes(peerPublicEphemeral), ephemeral.Private, dhGroup.DHParams().P).Bytes()
		transportKeys[name] = sha256.Sum256(key)
		return ct, nil
	}

	transport = func(id string, msg []byte) ([]byte, error) {
		k, ok := transportKeys[id]
		if !ok {
			return nil, errors.New("unknown sender")
		}
		block, err := aes.NewCipher(k[:])
		if err != nil {
			panic(err.Error())
		}

		nonce := bytes.Repeat([]byte{2}, 12)

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		payload, err := aesgcm.Open(nil, nonce, msg, nil)
		if err != nil {
			panic(err)
		}
		return []byte(fmt.Sprintf("Received from %s: %s", id, payload)), nil
	}

	isKeyCorrect = func(k []byte) bool {
		return bytes.Equal(k, key)
	}

	getPrivate = func() []byte {
		return static.Private.Bytes()
	}

	return discovery, handshake, transport, isKeyCorrect, getPrivate
}
