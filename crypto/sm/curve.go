package sm

import (
	"crypto/elliptic"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	sm2P256 elliptic.Curve

	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)

	B *big.Int
	N *big.Int
	P *big.Int
)

func init() {
	sm2P256 = sm2.P256Sm2()

	param := sm2P256.Params()
	B = param.B
	N = param.N
	P = param.P
}
