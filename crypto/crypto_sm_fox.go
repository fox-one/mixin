// +build sm,custom_alg,!cfca

package crypto

import (
	fsm "github.com/fox-one/crypto/sm/fox"
)

func init() {
	fsm.Load()
}
