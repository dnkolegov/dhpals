package dhpals

import (
	"errors"
	"fmt"
	"math/big"
)

var Big0 = big.NewInt(0)
var Big1 = big.NewInt(1)
var Big2 = big.NewInt(2)
var Big3 = big.NewInt(3)

// crt finds a solution of the system on m equations using the Chinese Reminder Theorem.
//
// Let n_1, ..., n_m be pairwise coprime (gcd(n_i, n_j) = 1, for different i,j).
// Then the system of m equations:
// x_1 = a_1 mod n_1
// ...
// x_m = a_m mod n_m
// has a unique solution for x modulo N = n_1 ... n_m
func crt(a, n []*big.Int) (*big.Int, *big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, p, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), p, nil
}

// divides returns true if x divides y.
func divides(x, y *big.Int) bool {
	return new(big.Int).Mod(y, x).Cmp(Big0) == 0
}

// phi computes Euler's totient function using a trivial straight-forward algorithm.
func phi(n *big.Int) *big.Int {
	res := new(big.Int).Set(n)
	m := new(big.Int).Sqrt(n)
	m.Add(m, Big1)
	cn := new(big.Int).Set(n)

	for i := new(big.Int).Set(Big2); i.Cmp(m) < 0; i.Add(i, Big1) {
		if divides(i, cn) {
			//v := new(big.Int).Set(n)
			for divides(i, cn) {
				cn.Div(cn, i)
			}
			e := new(big.Int).Div(res, i)
			res.Sub(res, e)
		}
	}
	if cn.Cmp(Big1) > 0 {
		e := new(big.Int).Div(res, cn)
		res.Sub(res, e)
	}
	return res
}

// es implements exhaustive search to find a discrete logarithm:
// x such that g ^ x = y mod n.
func es(g, y, n *big.Int) *big.Int {
	j := new(big.Int).SetInt64(0)
	for ; j.Cmp(n) < 0; j.Add(j, Big1) {
		if y.Cmp(new(big.Int).Exp(g, j, n)) == 0 {
			break
		}
	}
	return j
}

// bsgs implements the "baby-step giant-step" (Shenks-Gelfond) algorithm that
// finds x such that g ^ x = y mod n
func bsgs(g, y, p *big.Int) (*big.Int, error) {
	if g.Cmp(Big0) == 0 {
		return nil, errors.New("no solution in bsgs")
	}
	totient := phi(p)
	m := new(big.Int).Sqrt(totient)
	m.Add(m, Big1)
	state := make(map[string]*big.Int)

	for j := new(big.Int).Set(Big0); j.Cmp(m) < 0; j.Add(j, Big1) {
		c := new(big.Int).Exp(g, j, p)
		state[c.String()] = new(big.Int).Set(j)
	}
	g1 := new(big.Int).ModInverse(new(big.Int).Exp(g, m, p), p)

	q := new(big.Int).Set(y)

	for i := new(big.Int).Set(Big0); i.Cmp(m) < 0; i.Add(i, Big1) {
		if j, ok := state[q.String()]; ok {
			return m.Mul(m, i).Add(m, j).Mod(m, p), nil
		}
		q.Mul(q, g1)
		q.Mod(q, p)
	}

	return nil, errors.New("a solution was not found by bsgs")
}

// basicPohligHellman implements the basic Pohlig-Hellman algorithm on groups of prime order.
func basicPohligHellman(g, y, n, p, pf, ef *big.Int) *big.Int {
	gamma := new(big.Int).SetInt64(1)
	l := new(big.Int).SetInt64(0)
	q := new(big.Int).Set(pf)

	a1 := new(big.Int).Exp(g, new(big.Int).Div(n, q), p)

	x := new(big.Int).SetInt64(0)
	for j := new(big.Int).Set(Big0); j.Cmp(ef) < 0; j.Add(j, Big1) {

		aPower := new(big.Int).Mul(l, new(big.Int).Exp(q, new(big.Int).Sub(j, Big1), nil))

		a := new(big.Int).Exp(g, aPower, p)
		gamma.Mul(gamma, a)
		gamma.Mod(gamma, p)

		hh := new(big.Int).Exp(q, new(big.Int).Add(j, Big1), nil)
		betaPower := new(big.Int).Div(n, hh)
		beta := new(big.Int).ModInverse(gamma, p)
		beta.Mul(beta, y)
		beta.Exp(beta, betaPower, p)

		l, _ = bsgs(a1, beta, p)
		l.Mod(l, pf)

		dx := new(big.Int).Exp(pf, j, nil)
		dx.Mul(dx, l)
		x.Add(x, dx)
	}
	hhh := x.Mod(x, n)
	return hhh
}

// pohligHellman implements the general Pohlig-Hellman algorithm.
func pohligHellman(g, y, p *big.Int) *big.Int {
	var N, A []*big.Int
	n := phi(p)

	factors := factorize(n)

	for i := 0; i < len(factors); i++ {
		pf := factors[i].fact
		ef := new(big.Int).SetInt64(factors[i].exp)
		xx := basicPohligHellman(g, y, n, p, pf, ef)
		A = append(A, xx)
		N = append(N, new(big.Int).Exp(pf, ef, nil))
	}

	x, _, err := crt(A, N)
	if err != nil {
		panic(err)
	}
	return x
}
