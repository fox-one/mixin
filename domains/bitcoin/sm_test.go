// +build sm,custom_alg

package bitcoin

import "github.com/fox-one/mixin/crypto/sm"

func init() {
	sm.Load()
}
