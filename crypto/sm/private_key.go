// +build sm,custom_alg

package sm

import (
	"crypto/rand"
	"unsafe"

	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type PrivateKey sm.PrivateKey

var (
	defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func convertPrivateKey(p crypto.PrivateKey) *PrivateKey {
	switch v := p.(type) {
	case *PrivateKey:
		return v
	default:
		return nil
	}
}

func toSmPrivateKey(p *PrivateKey) *sm.PrivateKey {
	return (*sm.PrivateKey)(unsafe.Pointer(p))
}

func fromSmPrivateKey(p *sm.PrivateKey) *PrivateKey {
	return (*PrivateKey)(unsafe.Pointer(p))
}

func (p PrivateKey) String() string {
	return p.Key().String()
}

func (p *PrivateKey) Key() crypto.Key {
	return crypto.Key(toSmPrivateKey(p).Bytes())
}

func (p *PrivateKey) Public() crypto.PublicKey {
	return fromSmPublicKey(toSmPrivateKey(p).PublicKey())
}

func (p *PrivateKey) AddPrivate(p1 crypto.PrivateKey) crypto.PrivateKey {
	priv, err := sm.AddPrivate(toSmPrivateKey(p), toSmPrivateKey(convertPrivateKey(p1)))
	if err != nil {
		panic(err)
	}
	return fromSmPrivateKey(priv)
}

func (p PrivateKey) ScalarMult(pub crypto.PublicKey) crypto.PublicKey {
	s, err := sm.ScalarMult(toSmPrivateKey(&p), toSmPublicKey(convertPublicKey(pub)))
	if err != nil {
		panic(err)
	}

	return fromSmPublicKey(s)
}

func (p PrivateKey) SignWithChallenge(random crypto.PrivateKey, message []byte, hReduced [32]byte) (*crypto.Signature, error) {
	s, err := sm.Sign(rand.Reader, toSmPrivateKey(&p), message)
	if err != nil {
		return nil, err
	}
	sig := crypto.Signature(s)
	return &sig, nil
}

func (p PrivateKey) Sign(message []byte) (*crypto.Signature, error) {
	return p.SignWithChallenge(nil, message, [32]byte{})
}
