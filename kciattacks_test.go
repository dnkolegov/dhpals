package dhpals

import (
	"bytes"
	"testing"
)

func TestKCI(t *testing.T) {
	reply, err := runKCIAttack()
	if err != nil {
		t.Fatalf(t.Name(), ":", err)
	}
	kciReply := []byte("Received from Alice: Hello from Mallory")
	if !bytes.Equal(reply, kciReply) {
		t.Fatalf("%s: wanted %s, got %s", t.Name(), kciReply, reply)
	}

}
