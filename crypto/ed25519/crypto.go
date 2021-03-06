package ed25519

import (
	"errors"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/crypto/ed25519/edwards25519"
	"golang.org/x/crypto/sha3"
)

type keyFactory struct{}

func PrivateKeyFromSeed(seed []byte) (*Key, error) {
	var (
		src [64]byte
		out [32]byte
	)
	if len(seed) != len(src) {
		return nil, errors.New("invalid seed")
	}
	copy(src[:], seed)
	edwards25519.ScReduce(&out, &src)
	key := Key(out)
	if !key.CheckScalar() {
		return nil, errors.New("invalid key: check scalar failed")
	}
	return &key, nil
}

func (f keyFactory) PrivateKeyFromSeed(seed []byte) (crypto.PrivateKey, error) {
	return PrivateKeyFromSeed(seed)
}

func (f keyFactory) PrivateKeyFromKey(k crypto.Key) (crypto.PrivateKey, error) {
	var key = Key(k)
	if !key.CheckScalar() {
		return nil, errors.New("invalid key: check scalar failed")
	}
	return key, nil
}

func (f keyFactory) PublicKeyFromKey(k crypto.Key) (crypto.PublicKey, error) {
	var key = Key(k)
	if !key.CheckKey() {
		return nil, errors.New("invalid key: check key failed")
	}
	return key, nil
}

func Load() {
	crypto.SetKeyFactory(keyFactory{})
	crypto.SetHashFunc(sha3.Sum256)
}
