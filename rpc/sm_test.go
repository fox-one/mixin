// +build sm,custom_alg

package rpc

import "github.com/fox-one/mixin/crypto/sm"

func init() {
	sm.Load()
}
