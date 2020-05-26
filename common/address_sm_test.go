// +build sm custom_alg

package common

import (
	"testing"

	"github.com/MixinNetwork/mixin/crypto/sm"
	"github.com/stretchr/testify/assert"
)

func init() {
	sm.Load()
}

func TestAddress(t *testing.T) {
	assert := assert.New(t)

	seed := make([]byte, 64)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i + 1)
	}
	addr := "XIN7WejVFkLr9YcTHGzCaJ5YP8z6WVJgMqBZ5ZoUwyATj6c7TzcsYdpCVHGaRCQ85vqfVjzSmRaTLMZE9LJKfUsmKnBBHPFPPy"

	_, err := NewAddressFromString(addr[:95] + "7")
	assert.NotNil(err)

	a := NewAddressFromSeed(seed)
	assert.Equal(addr, a.String())
	assert.Equal("038bffc373bd388dbd45e3f6f02b23a005726dcb9e6db58ee594de77403a49c956", a.PublicViewKey.String())
	assert.Equal("028dff4906efc7ad05d04d5d277626144dc3bbb1427b301d2b91e4d8e9847b7142", a.PublicSpendKey.String())
	assert.Equal("00728ad9accee4b42943b80a5860d4779892c72c781a46a6ac42d6e94903da46e5", a.PrivateViewKey.String())
	assert.Equal("000a3c4ec76cbae822affe760cb34a5bc0554fa3cae96171a5b13565a1072e6a93", a.PrivateSpendKey.String())
	assert.Equal("98d846d6e71326857d14cd7467e3a773aaffaca884b92f486f7939c8a67f3432", a.Hash().String())

	j, err := a.MarshalJSON()
	assert.Nil(err)
	assert.Equal("\"XIN7WejVFkLr9YcTHGzCaJ5YP8z6WVJgMqBZ5ZoUwyATj6c7TzcsYdpCVHGaRCQ85vqfVjzSmRaTLMZE9LJKfUsmKnBBHPFPPy\"", string(j))
	err = a.UnmarshalJSON([]byte("\"XIN7WejVFkLr9YcTHGzCaJ5YP8z6WVJgMqBZ5ZoUwyATj6c7TzcsYdpCVHGaRCQ85vqfVjzSmRaTLMZE9LJKfUsmKnBBHPFPPy\""))
	assert.Nil(err)
	assert.Equal("038bffc373bd388dbd45e3f6f02b23a005726dcb9e6db58ee594de77403a49c956", a.PublicViewKey.String())
	assert.Equal("028dff4906efc7ad05d04d5d277626144dc3bbb1427b301d2b91e4d8e9847b7142", a.PublicSpendKey.String())
	assert.Nil(a.PrivateViewKey)
	assert.Nil(a.PrivateSpendKey)
	assert.Equal("98d846d6e71326857d14cd7467e3a773aaffaca884b92f486f7939c8a67f3432", a.Hash().String())

	b, err := NewAddressFromString(addr)
	assert.Nil(err)
	assert.Equal(addr, b.String())
	assert.Equal("038bffc373bd388dbd45e3f6f02b23a005726dcb9e6db58ee594de77403a49c956", b.PublicViewKey.String())
	assert.Equal("028dff4906efc7ad05d04d5d277626144dc3bbb1427b301d2b91e4d8e9847b7142", b.PublicSpendKey.String())
	assert.Nil(b.PrivateViewKey)
	assert.Nil(b.PrivateSpendKey)
	assert.Equal("98d846d6e71326857d14cd7467e3a773aaffaca884b92f486f7939c8a67f3432", b.Hash().String())

	z := NewAddressFromSeed(make([]byte, 64))
	assert.Equal("XIN7rUG6U7XyifQPW3HZFS9iLYYQrGp9X5mUJJzcUn3L45mMwKQN5D4hJJnfGKRoXFJSHkbTeU9jokwx9YGAjQFxmrk3sDyQxV", z.String())
}
