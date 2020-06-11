// +build sm,custom_alg

package crypto

import "github.com/fox-one/crypto/sm"

const (
	KeySize      = 33
	ResponseSize = 64
)

type Key [KeySize]byte
type Response [ResponseSize]byte
type Commitment Key

func init() {
	hashFunc = func(data []byte) [32]byte {
		return sm.Sm3Sum(data)
	}
}
