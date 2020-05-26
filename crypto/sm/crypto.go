package sm

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/tjfoc/gmsm/sm3"
)

type keyFactory struct{}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != 64 {
		return nil, errors.New("invalid seed")
	}
	h := crypto.NewHash(seed)

	var priv PrivateKey
	priv.D = new(big.Int).SetBytes(h[:])
	priv.D = priv.D.Mod(priv.D, sm2P256.Params().N)
	return &priv, nil
}

func NewPrivateKeyFromSeedOrPanic(seed []byte) *PrivateKey {
	key, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return key
}

func PrivateKeyFromKey(k crypto.Key) (*PrivateKey, error) {
	if k[0] != 0 {
		return nil, fmt.Errorf("invalid key with prefix: %d", k[0])
	}
	var priv PrivateKey
	priv.D = new(big.Int).SetBytes(k[1:])
	priv.D = priv.D.Mod(priv.D, sm2P256.Params().N)
	return &priv, nil
}

func PublicKeyFromKey(k crypto.Key) (*PublicKey, error) {
	if k[0] != 2 && k[0] != 3 {
		return nil, fmt.Errorf("invalid key with prefix: %d", k[0])
	}

	var pub PublicKey
	pub.X = new(big.Int).SetBytes(k[1:])
	pub.X = pub.X.Mod(pub.X, sm2P256.Params().P)

	xCubed := new(big.Int).Exp(pub.X, three, sm2P256.Params().P)
	threeX := new(big.Int).Mul(pub.X, three)
	threeX.Mod(threeX, sm2P256.Params().P)
	ySqured := new(big.Int).Sub(xCubed, threeX)
	ySqured.Add(ySqured, sm2P256.Params().B)
	ySqured.Mod(ySqured, sm2P256.Params().P)
	Y := new(big.Int).ModSqrt(ySqured, sm2P256.Params().P)
	if Y == nil {
		return nil, fmt.Errorf("invalid key value: %s", k)
	}

	if k[0] != byte(Y.Bit(0)+2) {
		Y = Y.Neg(Y)
		Y = Y.Mod(Y, sm2P256.Params().P)
	}
	pub.Y = Y
	return &pub, nil
}

func (f keyFactory) NewPrivateKeyFromSeed(seed []byte) (crypto.PrivateKey, error) {
	return NewPrivateKeyFromSeed(seed)
}

func (f keyFactory) NewPrivateKeyFromSeedOrPanic(seed []byte) crypto.PrivateKey {
	return NewPrivateKeyFromSeedOrPanic(seed)
}

func (f keyFactory) PrivateKeyFromKey(k crypto.Key) (crypto.PrivateKey, error) {
	return PrivateKeyFromKey(k)
}

func (f keyFactory) PublicKeyFromKey(k crypto.Key) (crypto.PublicKey, error) {
	return PublicKeyFromKey(k)
}

func Load() {
	crypto.SetKeyFactory(keyFactory{})
	crypto.SetHashFunc(func(data []byte) [32]byte {
		var h crypto.Hash
		copy(h[:], sm3.Sm3Sum(data))
		return h
	})
}
