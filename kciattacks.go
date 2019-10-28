package dhpals

import (
	"fmt"
	"math/big"

	"github.com/dnkolegov/dhpals/dhgroup"
)

func runKCIAttack() ([]byte, error) {
	var dhGroup, _ = dhgroup.GroupForGroupID(dhgroup.ModP2048)
	static, _ := dhGroup.GenerateKey(nil)
	ephemeral, _ := dhGroup.GenerateKey(nil)

	kem := dhkemScheme{group: dhGroup}

	discovery, handshake, transport, isKeyCorrect, getPrivate := newToxOracle(dhgroup.ModP2048)

	_, err := discovery("Alice", "set", static.Public.Bytes())

	peerPublicStatic, err := discovery("Bob", "get", nil)
	if err != nil {
		panic("unknown receiver")
	}

	ct := kem.Encap(static.Private, new(big.Int).SetBytes(peerPublicStatic), ephemeral.Public.Bytes())

	payload, _ := handshake("Alice", ct)

	peerPublicEphemeral := kem.Decap(static.Private, new(big.Int).SetBytes(peerPublicStatic), payload)

	key := new(big.Int).Exp(new(big.Int).SetBytes(peerPublicEphemeral), ephemeral.Private, dhGroup.DHParams().P).Bytes()

	if !isKeyCorrect(key) {
		panic("wrong shared key in KCI KEM")
	}

	// Suppose we have performed a cool attack and found Bob's private key.
	// Go ahead and impersonate Alice.
	secret := getPrivate()
	fmt.Println("Found private key:", secret)

	panic("not implemented")
	return transport("Alice", payload)

}
