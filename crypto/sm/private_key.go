// +build sm,custom_alg

package sm

import (
	"crypto/rand"

	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type PrivateKey struct {
	*sm.PrivateKey
	publicKey *PublicKey

	key *crypto.Key
}

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

func (p PrivateKey) String() string {
	return p.Key().String()
}

func (p *PrivateKey) Key() crypto.Key {
	if p.key == nil {
		key := crypto.Key(p.PrivateKey.Bytes())
		p.key = &key
	}
	return *p.key
}

func (p *PrivateKey) Public() crypto.PublicKey {
	if p.publicKey == nil {
		p.publicKey = &PublicKey{
			PublicKey: p.PrivateKey.PublicKey(),
		}
	}
	return p.publicKey
}

func (p PrivateKey) AddPrivate(p1 crypto.PrivateKey) crypto.PrivateKey {
	priv, err := p.PrivateKey.AddPrivate(*convertPrivateKey(p1).PrivateKey)
	if err != nil {
		panic(err)
	}
	return &PrivateKey{PrivateKey: priv}
}

func (p PrivateKey) ScalarMult(pub crypto.PublicKey) crypto.PublicKey {
	s, err := p.PrivateKey.ScalarMult(*convertPublicKey(pub).PublicKey)
	if err != nil {
		panic(err)
	}

	return &PublicKey{PublicKey: s}
}

func (p PrivateKey) SignWithChallenge(random crypto.PrivateKey, message []byte, hReduced [32]byte) (*crypto.Signature, error) {
	s, err := p.PrivateKey.Sign(rand.Reader, message)
	if err != nil {
		return nil, err
	}
	sig := crypto.Signature(s)
	return &sig, nil
}

func (p PrivateKey) Sign(message []byte) (*crypto.Signature, error) {
	return p.SignWithChallenge(nil, message, [32]byte{})
}
