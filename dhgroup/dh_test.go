package dhgroup

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDH(t *testing.T) {
	for _, v := range []ID{ModP512v57, ModP512v58, ModP768, ModP1536, ModP2048} {
		g, _ := GroupForGroupID(v)

		// Alice generates a key pair.
		a, err := g.GenerateKey(rand.Reader)
		if err != nil {
			t.Errorf("%s: Alice key generation failed for %s", t.Name(), g.DHName())
		}

		// Bog generates a key pair.
		b, err := g.GenerateKey(rand.Reader)
		if err != nil {
			t.Errorf("%s: Bob key generation failed for %s", t.Name(), g.DHName())
		}

		if bytes.Equal(b.Private.Bytes(), a.Private.Bytes()) || bytes.Equal(b.Public.Bytes(), a.Public.Bytes()) {
			t.Errorf("%s: Alice and Bob keys are the same for %s", t.Name(), g.DHName())
		}

		// Alice computes a shared key.
		zza, err := g.DH(a.Private, b.Public)
		if err != nil {
			t.Errorf("%s: Alice DH function failed for %s", t.Name(), g.DHName())
		}

		// Bob computes a shared key.
		zzb, err := g.DH(b.Private, a.Public)
		if err != nil {
			t.Errorf("%s: Bob DH function failed for %s", t.Name(), g.DHName())
		}

		if zza.Cmp(zzb) != 0 {
			t.Errorf("%s: Alice and Bob key agreement failed for %s", t.Name(), g.DHName())
		}
	}
}
