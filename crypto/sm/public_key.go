// +build sm,custom_alg

package sm

import (
	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type PublicKey struct {
	*sm.PublicKey

	key *crypto.Key
}

func convertPublicKey(p crypto.PublicKey) *PublicKey {
	switch v := p.(type) {
	case *PublicKey:
		return v
	default:
		return nil
	}
}

func (p *PublicKey) Key() crypto.Key {
	if p.key == nil {
		key := crypto.Key(p.PublicKey.Bytes())
		p.key = &key
	}
	return *p.key
}

func (p PublicKey) String() string {
	return p.Key().String()
}

func (p PublicKey) AddPublic(p1 crypto.PublicKey) crypto.PublicKey {
	pub, err := p.PublicKey.AddPublic(*convertPublicKey(p1).PublicKey)
	if err != nil {
		panic(err)
	}
	return &PublicKey{PublicKey: pub}
}

func (p PublicKey) SubPublic(p1 crypto.PublicKey) crypto.PublicKey {
	pub, err := p.PublicKey.SubPublic(*convertPublicKey(p1).PublicKey)
	if err != nil {
		panic(err)
	}
	return &PublicKey{PublicKey: pub}
}

func (p PublicKey) ScalarHash(outputIndex uint64) crypto.PrivateKey {
	return &PrivateKey{PrivateKey: p.PublicKey.ScalarHash(outputIndex)}
}

func (p PublicKey) DeterministicHashDerive() crypto.PrivateKey {
	return &PrivateKey{PrivateKey: p.PublicKey.DeterministicHashDerive()}
}

func (p PublicKey) Challenge(R crypto.PublicKey, message []byte) [32]byte {
	return [32]byte{}
}

func (p PublicKey) VerifyWithChallenge(message []byte, sig *crypto.Signature, hReduced [32]byte) bool {
	return p.Verify(message, sig)
}

func (p PublicKey) Verify(message []byte, sig *crypto.Signature) bool {
	return p.PublicKey.Verify(message, [64]byte(*sig))
}
