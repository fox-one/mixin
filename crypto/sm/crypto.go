// +build sm,custom_alg

package sm

import (
	"errors"
	"fmt"

	"github.com/fox-one/crypto/sm"
	"github.com/fox-one/mixin/crypto"
)

type keyFactory struct{}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != 64 {
		return nil, errors.New("invalid seed")
	}
	h := crypto.NewHash(seed)
	var key [33]byte
	copy(key[1:], h[:])
	priv, err := sm.PrivateKeyFromBytes(&key)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{PrivateKey: priv}, nil
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
	key := [33]byte(k)
	priv, err := sm.PrivateKeyFromBytes(&key)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{PrivateKey: priv}, nil
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
	return &PublicKey{PublicKey: pub}, nil
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
		return sm.Sm3Sum(data)
	})
}
