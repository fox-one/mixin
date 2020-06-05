package sm

import (
	"fmt"
	"math/big"

	"github.com/fox-one/mixin/crypto"
	"github.com/tjfoc/gmsm/sm2"
)

type PublicKey struct {
	X, Y *big.Int

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
		var key crypto.Key
		xBts := p.X.Bytes()
		copy(key[len(key)-len(xBts):], xBts)
		key[0] = byte(2 + p.Y.Bit(0))
		p.key = &key
	}
	return *p.key
}

func (p PublicKey) String() string {
	return p.Key().String()
}

func (p PublicKey) AddPublic(p1 crypto.PublicKey) crypto.PublicKey {
	s := PublicKey{}
	pub1 := convertPublicKey(p1)
	if pub1 == nil {
		panic(fmt.Errorf("invalid public key: %v", p1))
	}
	s.X, s.Y = sm2P256.Add(p.X, p.Y, pub1.X, pub1.Y)
	return &s
}

func (p PublicKey) SubPublic(p1 crypto.PublicKey) crypto.PublicKey {
	s := PublicKey{}
	pub1 := convertPublicKey(p1)
	if pub1 == nil {
		panic(fmt.Errorf("invalid public key: %v", p1))
	}
	Y1 := new(big.Int).Neg(pub1.Y)
	s.X, s.Y = sm2P256.Add(p.X, p.Y, pub1.X, Y1)
	return &s
}

func (p PublicKey) ScalarHash(outputIndex uint64) crypto.PrivateKey {
	data := append(p.X.Bytes(), big.NewInt(int64(outputIndex)).Bytes()...)
	data = append(data, p.Y.Bytes()...)
	h := crypto.NewHash(data)
	h = crypto.NewHash(append(data, h[:]...))

	priv := PrivateKey{}
	priv.D = new(big.Int).SetBytes(h[:])
	priv.D = priv.D.Mod(priv.D, N)
	return &priv
}

func (p PublicKey) DeterministicHashDerive() crypto.PrivateKey {
	data := append(p.X.Bytes(), p.Y.Bytes()...)
	h := crypto.NewHash(data)

	priv := PrivateKey{}
	priv.D = new(big.Int).SetBytes(h[:])
	priv.D = priv.D.Mod(priv.D, N)
	return &priv
}

func (p PublicKey) Challenge(R crypto.PublicKey, message []byte) [32]byte {
	return [32]byte{}
}

func (p PublicKey) VerifyWithChallenge(message []byte, sig *crypto.Signature, hReduced [32]byte) bool {
	return p.Verify(message, sig)
}

func (p PublicKey) Verify(message []byte, sig *crypto.Signature) bool {
	pub := new(sm2.PublicKey)
	pub.Curve = sm2P256
	pub.X, pub.Y = p.X, p.Y
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return sm2.Sm2Verify(pub, message, defaultUID, r, s)
}
