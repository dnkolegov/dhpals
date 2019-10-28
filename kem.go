package dhpals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/dnkolegov/dhpals/dhgroup"
)

type KEMPrivateKey interface{}

type KEMPublicKey interface{}

type dhkemScheme struct {
	group dhgroup.DHScheme
}

func (g dhkemScheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	key, _ := g.group.GenerateKey(rand)
	return key.Private, key.Public, nil
}

func (g dhkemScheme) Encap(priv KEMPrivateKey, pub KEMPublicKey, payload []byte) []byte {
	dhPriv, ok := priv.(*big.Int)
	if !ok {
		panic("Private key not suitable for DH")
	}
	dhPub, ok := pub.(*big.Int)
	if !ok {
		panic("Public key not suitable for DH")
	}
	zz := new(big.Int).Exp(dhPub, dhPriv, g.group.DHParams().P)

	k := sha256.Sum256(zz.Bytes())

	block, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err.Error())
	}

	nonce := bytes.Repeat([]byte{1}, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ct := aesgcm.Seal(nil, nonce, payload, nil)
	return ct
}

func (g dhkemScheme) Decap(priv KEMPrivateKey, pub KEMPublicKey, ct []byte) []byte {
	dhPriv, ok := priv.(*big.Int)
	if !ok {
		panic("Private key not suitable for DH")
	}
	dhPub, ok := pub.(*big.Int)
	if !ok {
		panic("Public key not suitable for DH")
	}
	zz := new(big.Int).Exp(dhPub, dhPriv, g.group.DHParams().P)

	k := sha256.Sum256(zz.Bytes())

	block, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err.Error())
	}

	nonce := bytes.Repeat([]byte{1}, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	payload, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		panic(err)
	}
	return payload
}
