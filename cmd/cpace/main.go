// Command cpace demonstrates why map_to_curve is necessary for
// CPace.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/hkdf"
)

func main() {
	list := []string{"foo", "bar", "baz"}

	mapToCurve := func(pass string) *ristretto255.Element {
		var e ristretto255.Element
		_, err := e.SetUniformBytes(hash64(pass))
		if err != nil {
			panic(err)
		}
		return &e
	}
	fmt.Print("testing with map_to_curve... ")
	if err := guess(mapToCurve, "baz", list...); err != nil {
		log.Fatal(err)
	}
	fmt.Println("PASS")

	notMapToCurve := func(pass string) *ristretto255.Element {
		var s ristretto255.Scalar
		_, err := s.SetUniformBytes(hash64(pass))
		if err != nil {
			panic(err)
		}
		var e ristretto255.Element
		return e.ScalarBaseMult(&s)
	}
	fmt.Print("testing without map_to_curve... ")
	if err := guess(notMapToCurve, "baz", list...); err != nil {
		fmt.Printf("FAIL\n\t%v\n", err)
	}
}

func guess(mapToCurve func(string) *ristretto255.Element, pass string, guesses ...string) error {
	// Alice and Bob are trying to perform PAKE.
	//
	// An attacker inserts himself between Alice and Bob,
	// pretending to be Alice.
	//
	// He sends over MSGa (Ya) using his guess at what the
	// password is.
	var ya ristretto255.Scalar
	ya.SetUniformBytes(randBytes(64))
	var Ya ristretto255.Element
	Ya.ScalarMult(&ya, mapToCurve(guesses[0])) // send to Bob

	// Bob, who knows the password, correctly generates MSGb.
	//
	// He sends MSGb (Yb) to Alice (and subsequently the
	// attacker).
	var yb ristretto255.Scalar
	yb.SetUniformBytes(randBytes(64))
	var Yb ristretto255.Element
	Yb.ScalarMult(&yb, mapToCurve(pass)) // send to "Alice"

	// Bob receives the attacker's MSGa (Ya), computes ISK, and
	// encrypts some plaintext.
	var K ristretto255.Element
	K.ScalarMult(&yb, &Ya)
	ISK := hash32(K.Bytes())
	ciphertext := seal(ISK, []byte("hello, world!"))

	// If CPace is working correctly then the attacker should not
	// be able to continue his attack past the first guess.

	var s ristretto255.Scalar
	s.SetUniformBytes(hash64(guesses[0]))
	for _, guess := range guesses {
		// Without map_to_curve the attacker can calculate
		//    ya_i = H(p) * H(p_i)^-1 * ya
		//    Yb_i = H(p_i)G
		// and since
		//    [ya_i]Yb_i = [ya]Yb
		// the attacker can simply save Yb and test each
		// candidate password offline.
		var yai ristretto255.Scalar
		_, err := yai.SetUniformBytes(hash64(guess))
		if err != nil {
			return err
		}
		yai.Invert(&yai).
			Multiply(&yai, &s).
			Multiply(&yai, &ya)

		var K ristretto255.Element
		K.ScalarMult(&yai, &Yb)
		ISK := hash32(K.Bytes())

		plaintext, err := open(ISK, ciphertext)
		if err == nil {
			return fmt.Errorf("recovered plaintext: %q", plaintext)
		}
	}
	return nil
}

func seal(key, plaintext []byte) []byte {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	nonce := randBytes(gcm.NonceSize())
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...)
}

func open(key, ciphertext []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func randBytes(n int) []byte {
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		panic(err)
	}
	return p
}

func hash32(data []byte) []byte {
	h := hkdf.New(sha256.New, data, nil, nil)
	b := make([]byte, 32)
	if _, err := h.Read(b); err != nil {
		panic(err)
	}
	return b
}

func hash64(v any) []byte {
	var data []byte
	switch t := v.(type) {
	case string:
		data = []byte(t)
	case []byte:
		data = t
	default:
		panic("unknown type")
	}
	h := hkdf.New(sha256.New, data, nil, nil)
	b := make([]byte, 64)
	if _, err := h.Read(b); err != nil {
		panic(err)
	}
	return b
}
