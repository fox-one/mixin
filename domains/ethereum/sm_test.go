// +build sm,custom_alg

package ethereum

import "github.com/fox-one/mixin/crypto/sm"

func init() {
	sm.Load()
}
