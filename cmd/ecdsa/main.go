// Command k demonstrates breaking ECDSA private keys with weak,
// leaked, or reused nonces.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	l3 "github.com/ericlagergren/ctb/lll"
	"golang.org/x/crypto/chacha20"
)

func init() {
	curve := elliptic.P256()
	M := []byte("hello, world!")
	r, _ := new(big.Int).SetString("c5363ca0229aa1487026dc77c2abc09dba6b4dce6cc879a07afbe14122316c9a", 16)
	s, _ := new(big.Int).SetString("6ae8ceeaa0661e3ba0fed6530b3a661c01c744009e833d44b87861b9b8e5320d", 16)
	K, _ := new(big.Int).SetString("02020201fefefeff01445d62b55152b9866561ee015f71beb49fb020554e145f", 16)
	N := curve.Params().N
	e := hashToInt(H(M), curve)
	reveal1(r, s, K, N, e)
}

func main() {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("leaked k #1: %x\n", leakK(priv, true))
	// fmt.Printf("leaked k #2: %x\n", leakK(priv, false))
	// fmt.Printf("reused k   : %x\n", reuseK(priv))
	// fmt.Printf("actual     : %x\n", priv.D)

	for i := 0; i < 1; i++ {
		D := lattice(priv)
		if D.Sign() != 0 {
			fmt.Printf("#%d: LLL:       : %x\n", i, D)
			break
		}
	}
}

func lattice(priv *ecdsa.PrivateKey) *big.Int {
	curve := elliptic.P256()

	priv = &(*priv)
	priv.D, _ = new(big.Int).SetString("78820416530262976955738813433175776840628733537564602790902190607542488847122", 10)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(priv.D.Bytes())

	N := curve.Params().N

	M1 := []byte("hello, world!")
	M2 := []byte("!dlrow ,olleh")

	h := sha256.New()
	h.Write(M1)
	hash1 := h.Sum(nil)
	h.Reset()
	h.Write(M2)
	hash2 := h.Sum(nil)

	const _W = 128
	B := big.NewInt(1)
	B.Lsh(B, _W)
	Bm1 := big.NewInt(1)
	Bm1.Lsh(Bm1, _W-1)
	k1, _ := new(big.Int).SetString("152980802533694987400421914292345709688", 10)
	k2, _ := new(big.Int).SetString("23479681102223137409793422985451094498", 10)
	// k1, _ := rand.Int(rand.Reader, Bm1)
	// k2, _ := rand.Int(rand.Reader, Bm1)

	r1, s1, err := SignWithNonce(priv, hash1, k1)
	if err != nil {
		panic(err)
	}
	sm1 := new(big.Int).ModInverse(s1, N)
	fmt.Println(r1)
	fmt.Println(sm1)
	r1s1 := new(big.Int).Mul(r1, sm1)
	// r1s1.Mod(r1s1, N)

	r2, s2, err := SignWithNonce(priv, hash2, k2)
	if err != nil {
		panic(err)
	}
	sm2 := new(big.Int).ModInverse(s2, N)
	r2s2 := new(big.Int).Mul(r2, sm2)
	// r2s2.Mod(r2s2, N)

	m1 := hashToInt(M1, curve)
	m1s1 := new(big.Int).Mul(m1, sm1)
	// m1s1.Mod(m1s1, N)

	m2 := hashToInt(M2, curve)
	m2s2 := new(big.Int).Mul(m2, sm2)
	// m2s2.Mod(m2s2, N)

	zero := l3.I64(0)
	basis := [][]l3.T{
		{l3.I(N), zero, zero, zero},
		{zero, l3.I(N), zero, zero},
		{l3.I(r1s1), l3.I(r2s2), l3.F(B, N), zero},
		{l3.I(m1s1), l3.I(m2s2), zero, l3.I(B)},
	}
	fmt.Println(basis)
	mx := l3.Reduction(l3.F64(3, 4), basis)
	fmt.Println(mx)
	for _, row := range mx {
		var k big.Int
		l3.SetInt(&k, row[0])
		fmt.Println("k: ", &k)
		D := reveal1(r1, s1, &k, N, m1)
		fmt.Println("D :", priv.D)
		fmt.Println("D':", D)
		if D.Cmp(priv.D) == 0 {
			return D
		}
	}
	return new(big.Int)
}

// leakK recovers a private key
func leakK(priv *ecdsa.PrivateKey, stdlib bool) *big.Int {
	M := []byte("hello, world!")
	hash := H(M)

	var buf bytes.Buffer
	rng := antiMaybeReader{io.TeeReader(rand.Reader, &buf)}

	var r, s *big.Int
	var err error
	if stdlib {
		r, s, err = ecdsa.Sign(rng, priv, hash)
	} else {
		r, s, err = Sign(rng, priv, hash)
	}
	if err != nil {
		panic(err)
	}

	curve := priv.Curve
	K := buildK(&buf, curve, priv.D, hash, stdlib)
	N := curve.Params().N
	return reveal1(r, s, K, N, hashToInt(hash, curve))
}

func reuseK(priv *ecdsa.PrivateKey) *big.Int {
	M1 := []byte("hello, world!")
	M2 := []byte("!dlrow ,olleh")

	rng := func() io.Reader {
		key := make([]byte, 32)
		nonce := make([]byte, chacha20.NonceSizeX)
		s, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}
		r := &cipher.StreamReader{
			S: s,
			R: zeroReader{},
		}
		return antiMaybeReader{r}
	}

	hash1 := H(M1)
	r1, s1, err := Sign(rng(), priv, hash1)
	if err != nil {
		panic(err)
	}

	hash2 := H(M2)
	r1, s2, err := Sign(rng(), priv, hash2)
	if err != nil {
		panic(err)
	}

	curve := priv.Curve
	N := curve.Params().N

	e1 := hashToInt(hash1, curve)
	e2 := hashToInt(hash2, curve)
	return reveal2(r1, s1, s2, N, e1, e2)
}

// reveal1 reconstructs the private key from a signature (r, s), message e,
// leaked nonce k, and curve order N.
func reveal1(r, s, k, N, e *big.Int) *big.Int {
	// r = k*G
	// s = k^-1(H(M) + r*priv)
	// x = r^-1*((k*s) - H(M))
	ks := new(big.Int)
	ks = ks.Mul(k, s)
	ks = ks.Mod(ks, N)
	ks = ks.Sub(ks, e)

	x := new(big.Int).ModInverse(r, N)
	x = x.Mul(x, ks)
	x = x.Mod(x, N)
	return x
}

// reveal2 reconstructs the private key from two signtures (r1, s1) and (r1, s2),
// the signatures' respective messages e1 and e2, and the curve order N.
func reveal2(r, s1, s2, N, e1, e2 *big.Int) *big.Int {
	// r1 = k*G
	// s1 = k^-1(H(M1) + r1*priv)
	// r2 = k*G
	// s2 = k^-1(H(M2) + r2*priv)
	// s1 - s2 = k^-1(H(M1) - H(M2))
	// k(s1-s2) = H(M1) - H(M2)
	// k = (s1-s2)^-1(H(M1) - H(M2))
	k := new(big.Int)
	k = k.Sub(s1, s2)
	k = k.ModInverse(k, N)
	k = k.Mul(k, new(big.Int).Sub(e1, e2))
	k = k.Mod(k, N)
	return reveal1(r, s1, k, N, e1)
}

// H returns SHA-256(M).
func H(M []byte) []byte {
	h := sha256.New()
	h.Write(M)
	return h.Sum(nil)
}

// antiMaybeReader ignores one-byte reads.
//
// The stdlib performs one-byte reads with 50% probability so that applications
// do not use deterministic RNGs.
type antiMaybeReader struct {
	r io.Reader
}

var _ io.Reader = antiMaybeReader{}

func (r antiMaybeReader) Read(p []byte) (int, error) {
	if len(p) == 1 {
		return 1, nil
	}
	return r.r.Read(p)
}

func buildK(rand io.Reader, curve elliptic.Curve, D *big.Int, hash []byte, stdlib bool) *big.Int {
	rng := rand
	if stdlib {
		// Get min(log2(q) / 2, 256) bits of entropy from rand.
		entropylen := (curve.Params().BitSize + 7) / 16
		if entropylen > 32 {
			entropylen = 32
		}
		entropy := make([]byte, entropylen)
		_, err := io.ReadFull(rand, entropy)
		if err != nil {
			panic(err)
		}

		// Initialize an SHA-512 hash context; digest ...
		md := sha512.New()
		md.Write(D.Bytes())     // the private key,
		md.Write(entropy)       // the entropy,
		md.Write(hash)          // and the input hash;
		key := md.Sum(nil)[:32] // and compute ChopMD-256(SHA-512),
		// which is an indifferentiable MAC.

		// Create an AES-CTR instance to use as a CSPRNG.
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		// Create a CSPRNG that xors a stream of zeros with
		// the output of the AES-CTR instance.
		rng = &cipher.StreamReader{
			R: zeroReader{},
			S: cipher.NewCTR(block, []byte("IV for ECDSA CTR")),
		}
	}
	for {
		k, err := randFieldElement(curve, rng)
		if err != nil {
			panic(err)
		}
		r, _ := curve.ScalarBaseMult(k.Bytes())
		r.Mod(r, curve.Params().N)
		if r.Sign() != 0 {
			return k
		}
	}
}

// Sign is ecdsa.Sign but without using a deterministic CSPRNG for generating k.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	c := priv.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errors.New("zero parameter")
	}
	var k, kInv *big.Int
	for {
		for {
			k, err = randFieldElement(c, rand)
			if err != nil {
				r = nil
				return
			}

			kInv = new(big.Int).ModInverse(k, N) // N != 0

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func SignWithNonce(priv *ecdsa.PrivateKey, hash []byte, k *big.Int) (r, s *big.Int, err error) {
	c := priv.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errors.New("zero parameter")
	}
	kInv := new(big.Int).ModInverse(k, N) // N != 0
	e := hashToInt(hash, c)
	r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
	r.Mod(r, N)
	s = new(big.Int).Mul(priv.D, r)
	s.Add(s, e)
	s.Mul(s, kInv)
	s.Mod(s, N) // N != 0
	return
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

var one = big.NewInt(1)

type zeroReader struct{}

var _ io.Reader = zeroReader{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
