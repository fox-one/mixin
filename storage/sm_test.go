// +build sm,custom_alg

package storage

import "github.com/fox-one/mixin/crypto/sm"

var configFilePath = "../config/config.example.sm.toml"

func init() {
	sm.Load()
}
