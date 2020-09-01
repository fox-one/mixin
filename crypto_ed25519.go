// +build ed25519 !custom_alg

package main

import "github.com/fox-one/mixin/crypto/ed25519"

func init() {
	ed25519.Load()
}
