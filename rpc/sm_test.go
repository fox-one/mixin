// +build sm custom_alg

package rpc

import "github.com/MixinNetwork/mixin/crypto/sm"

func init() {
	sm.Load()
}
