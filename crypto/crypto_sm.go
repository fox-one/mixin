// +build sm custom_alg

package crypto

import (
	"github.com/tjfoc/gmsm/sm3"
)

const (
	KeySize      = 33
	ResponseSize = 64
)

type Key [KeySize]byte
type Response [ResponseSize]byte
type Commitment Key

func init() {
	hashFunc = func(data []byte) [32]byte {
		var h Hash
		copy(h[:], sm3.Sm3Sum(data))
		return h
	}
}
