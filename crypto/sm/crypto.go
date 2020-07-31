package sm

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type keyFactory struct{}

func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != 64 {
		return nil, errors.New("invalid seed")
	}
	h := crypto.NewHash(seed)
	return PrivateKeyFromInteger(new(big.Int).SetBytes(h[:]))
}

func PrivateKeyFromSeedOrPanic(seed []byte) *PrivateKey {
	key, err := PrivateKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return key
}

func PrivateKeyFromInteger(d *big.Int) (*PrivateKey, error) {
	p, err := sm.PrivateKeyFromInteger(d)
	if err != nil {
		return nil, err
	}
	return fromSmPrivateKey(p), nil
}

func PrivateKeyFromKey(k crypto.Key) (*PrivateKey, error) {
	if k[0] != 0 {
		return nil, fmt.Errorf("invalid key with prefix: %d", k[0])
	}
	return PrivateKeyFromInteger(new(big.Int).SetBytes(k[1:]))
}

func PublicKeyFromKey(k crypto.Key) (*PublicKey, error) {
	if k[0] != 2 && k[0] != 3 {
		return nil, fmt.Errorf("invalid key with prefix: %d", k[0])
	}

	key := [33]byte(k)
	pub, err := sm.PublicKeyFromBytes(&key)
	if err != nil {
		return nil, err
	}
	return fromSmPublicKey(pub), nil
}

func (f keyFactory) PrivateKeyFromSeed(seed []byte) (crypto.PrivateKey, error) {
	return PrivateKeyFromSeed(seed)
}

func (f keyFactory) PrivateKeyFromSeedOrPanic(seed []byte) crypto.PrivateKey {
	return PrivateKeyFromSeedOrPanic(seed)
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
		return sm.Sm3Sum(data)
	})
}
