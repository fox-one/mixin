package sm

import (
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/tjfoc/gmsm/sm2"
)

type PrivateKey struct {
	PublicKey *PublicKey
	D         *big.Int

	key *crypto.Key
}

var (
	defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func convertPrivateKey(p crypto.PrivateKey) *PrivateKey {
	switch v := p.(type) {
	case PrivateKey:
		return &v
	case *PrivateKey:
		return v
	default:
		return nil
	}
}

func (p PrivateKey) String() string {
	return p.Key().String()
}

func (p PrivateKey) Key() crypto.Key {
	if p.key == nil {
		var key crypto.Key
		copy(key[1:], p.D.Bytes()[:])
		p.key = &key
	}
	return *p.key
}

func (p PrivateKey) Public() crypto.PublicKey {
	if p.PublicKey == nil {
		var pub PublicKey
		pub.X, pub.Y = sm2P256.ScalarBaseMult(p.D.Bytes())
		p.PublicKey = &pub
	}
	return p.PublicKey
}

func (p PrivateKey) AddPrivate(p1 crypto.PrivateKey) crypto.PrivateKey {
	s := PrivateKey{}
	priv1 := convertPrivateKey(p1)
	if priv1 == nil {
		panic(fmt.Errorf("invalid private key: %v", p1))
	}
	s.D = new(big.Int).Add(p.D, priv1.D)
	s.D = s.D.Mod(s.D, sm2P256.Params().N)
	return &s
}

func (p PrivateKey) ScalarMult(pub crypto.PublicKey) crypto.PublicKey {
	pubK := convertPublicKey(pub)
	if pubK == nil {
		panic(fmt.Errorf("invalid public key: %v", pub))
	}
	var s PublicKey
	s.X, s.Y = sm2P256.ScalarMult(pubK.X, pubK.Y, p.D.Bytes())
	return &s
}

func (p PrivateKey) SignWithChallenge(random crypto.PrivateKey, message []byte, hReduced [32]byte) (*crypto.Signature, error) {
	pub := convertPublicKey(p.Public())

	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = sm2P256
	priv.D = p.D
	priv.X, priv.Y = pub.X, pub.Y
	r, s, err := sm2.Sm2Sign(priv, message, defaultUID)
	if err != nil {
		return nil, err
	}
	var sig crypto.Signature
	rBts := r.Bytes()
	sBts := s.Bytes()
	copy(sig[32-len(rBts):32], rBts)
	copy(sig[64-len(sBts):], s.Bytes())
	return &sig, nil
}

func (p PrivateKey) Sign(message []byte) (*crypto.Signature, error) {
	return p.SignWithChallenge(nil, message, [32]byte{})
}
