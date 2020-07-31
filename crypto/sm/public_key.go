package sm

import (
	"unsafe"

	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type PublicKey sm.PublicKey

var (
	emptyChallenge [32]byte
)

func convertPublicKey(p crypto.PublicKey) *PublicKey {
	switch v := p.(type) {
	case *PublicKey:
		return v
	default:
		return nil
	}
}

func toSmPublicKey(p *PublicKey) *sm.PublicKey {
	return (*sm.PublicKey)(unsafe.Pointer(p))
}

func fromSmPublicKey(p *sm.PublicKey) *PublicKey {
	return (*PublicKey)(unsafe.Pointer(p))
}

func (p *PublicKey) Key() crypto.Key {
	return crypto.Key(toSmPublicKey(p).Bytes())
}

func (p PublicKey) String() string {
	return p.Key().String()
}

func (p PublicKey) AddPublic(p1 crypto.PublicKey) crypto.PublicKey {
	pub, err := sm.AddPublic(toSmPublicKey(&p), toSmPublicKey(convertPublicKey(p1)))
	if err != nil {
		panic(err)
	}
	return fromSmPublicKey(pub)
}

func (p PublicKey) SubPublic(p1 crypto.PublicKey) crypto.PublicKey {
	pub, err := sm.SubPublic(toSmPublicKey(&p), toSmPublicKey(convertPublicKey(p1)))
	if err != nil {
		panic(err)
	}
	return fromSmPublicKey(pub)
}

func (p PublicKey) ScalarHash(outputIndex uint64) crypto.PrivateKey {
	return fromSmPrivateKey(sm.ScalarHash(toSmPublicKey(&p), outputIndex))
}

func (p PublicKey) DeterministicHashDerive() crypto.PrivateKey {
	return fromSmPrivateKey(sm.DeterministicHashDerive(toSmPublicKey(&p)))
}

func (p PublicKey) Challenge(R crypto.PublicKey, message []byte) [32]byte {
	return emptyChallenge
}

func (p PublicKey) VerifyWithChallenge(message []byte, sig *crypto.Signature, hReduced [32]byte) bool {
	return p.Verify(message, sig)
}

func (p PublicKey) Verify(message []byte, sig *crypto.Signature) bool {
	return sm.Verify(toSmPublicKey(&p), message, [64]byte(*sig))
}
