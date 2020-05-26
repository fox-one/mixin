package sm

import (
	"crypto/elliptic"

	"github.com/tjfoc/gmsm/sm2"
)

var sm2P256 elliptic.Curve

func init() {
	sm2P256 = sm2.P256Sm2()
}
