// +build sm custom_alg

package bitcoin

import "github.com/MixinNetwork/mixin/crypto/sm"

func init() {
	sm.Load()
}
