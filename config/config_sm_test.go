// +build sm,custom_alg

package config

import (
	"testing"

	"github.com/fox-one/mixin/crypto/sm"
	"github.com/stretchr/testify/assert"
)

func init() {
	sm.Load()
}

func TestConfig(t *testing.T) {
	assert := assert.New(t)

	custom, err := Initialize("./config.example.sm.toml")
	assert.Nil(err)

	assert.Equal("00068fd928a48d08d930c50c7d762403ce4380cbb608e5cf95fc864efcd5b3b209", custom.Node.Signer.String())
	assert.Equal(false, custom.Node.ConsensusOnly)
	assert.Equal(700, custom.Node.KernelOprationPeriod)
	assert.Equal(16384, custom.Node.MemoryCacheSize)
	assert.Equal(7200, custom.Node.CacheTTL)
	assert.Equal(uint64(1048576), custom.Node.RingCacheSize)
	assert.Equal(uint64(16777216), custom.Node.RingFinalSize)
	assert.Equal("mixin-node.example.com:7239", custom.Network.Listener)
	assert.Equal(false, custom.RPC.Runtime)
}