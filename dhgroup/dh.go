// Package dhgroup implements Diffie-Hellman key agreement on a multiplicative group.
package dhgroup

import (
	"fmt"
	"io"
	"math/big"
	"sync"
)

// ID is the identifier of a DH group.
type ID uint16

const (
	ModP512v57 ID = 57
	ModP512v58 ID = 58
	ModP768    ID = 101
	ModP1536   ID = 102
	ModP2048   ID = 103
)

type DHKey struct {
	Private *big.Int
	Public  *big.Int
}

type DHScheme interface {
	// GenerateECKeyPair generates a new key pair using random as a source of
	// entropy.
	GenerateKey(random io.Reader) (DHKey, error)

	// DH performs a Diffie-Hellman calculation between the provided private and
	// public keys and returns the result.
	DH(private, public *big.Int) (*big.Int, error)

	// DHLen is the number of bites returned by DH.
	DHLen() int

	// DHName is the name of the DH function.
	DHName() string

	// DHParams returns the parameters of the group.
	DHParams() *GroupParams
}

// GroupParams contains the parameters of an DH group and also provides
// a generic, non-constant time implementation of DH.
type GroupParams struct {
	P       *big.Int
	G       *big.Int
	Q       *big.Int
	Name    string
	BitSize int
}

func (g *GroupParams) DHParams() *GroupParams {
	return g
}

func (g GroupParams) GenerateKey(rng io.Reader) (DHKey, error) {
	panic("Not implemented")
	return DHKey{
		Private: nil,
		Public:  nil,
	}, nil
}

func (g GroupParams) DH(private, public *big.Int) (*big.Int, error) {
	panic("not implemented")
	return nil, nil
}

func (g GroupParams) DHLen() int {
	return g.BitSize
}

func (g GroupParams) DHName() string {
	return g.Name
}

// Groups from RFC 3526 - https://datatracker.ietf.org/doc/rfc3526/?include_text=1.

var modp768 *GroupParams
var modp1536 *GroupParams
var modp2048 *GroupParams
var modp512v57 *GroupParams
var modp512v58 *GroupParams

func initAll() {
	initMODP768()
	initMODP1536()
	initMODP2048()
	initMODP512V57()
	initMODP512V58()
}

var initonce sync.Once

func initMODP768() {

	modp768 = &GroupParams{Name: "MODP-768"}
	modp768.P = bigFromBase16("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF")
	modp768.G = big.NewInt(2)
	modp768.Q = new(big.Int).Sub(modp768.P, big.NewInt(1))
	modp768.BitSize = 768
}

func initMODP1536() {

	modp1536 = &GroupParams{Name: "MODP-1536"}
	modp1536.P = bigFromBase16("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
		"fffffffffffff")
	modp1536.G = big.NewInt(2)
	modp1536.Q = new(big.Int).Sub(modp1536.P, big.NewInt(1))
	modp1536.BitSize = 1536
}

func initMODP2048() {
	modp2048 = &GroupParams{Name: "MODP-2048"}
	modp2048.P = bigFromBase16("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF")
	modp2048.G = big.NewInt(2)
	modp2048.Q = new(big.Int).Sub(modp2048.P, big.NewInt(1))
	modp2048.BitSize = 2048
}

// Cryptopals groups.
func initMODP512V57() {
	modp512v57 = &GroupParams{Name: "MODP-512-V57"}
	modp512v57.P = bigFromBase10("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771")
	modp512v57.G = bigFromBase10("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143")
	modp512v57.Q = bigFromBase10("236234353446506858198510045061214171961")
	modp512v57.BitSize = 512
}

func initMODP512V58() {
	modp512v58 = &GroupParams{Name: "MODP512-V58"}
	modp512v58.P = bigFromBase10("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623")
	modp512v58.G = bigFromBase10("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357")
	modp512v58.Q = bigFromBase10("335062023296420808191071248367701059461")
	modp512v58.BitSize = 512
}

func MODP768() DHScheme {
	initonce.Do(initAll)
	return modp768
}

func MODP1536() DHScheme {
	initonce.Do(initAll)
	return modp1536
}

func MODP2048() DHScheme {
	initonce.Do(initAll)
	return modp2048
}

func MODP512V57() DHScheme {
	initonce.Do(initAll)
	return modp512v57
}

func MODP512V58() DHScheme {
	initonce.Do(initAll)
	return modp512v58
}

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func bigFromBase16(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

func GroupForGroupID(groupID ID) (group DHScheme, err error) {
	switch groupID {
	case ModP512v57:
		group = MODP512V57()
	case ModP512v58:
		group = MODP512V58()
	case ModP768:
		group = MODP768()
	case ModP1536:
		group = MODP1536()
	case ModP2048:
		group = MODP2048()
	default:
		group = nil
		err = fmt.Errorf("dhgroup: Unknown or unsupported group id: %d", groupID)
	}
	return
}
