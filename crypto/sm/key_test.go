package sm

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/fox-one/mixin/crypto"
	"github.com/stretchr/testify/assert"
)

func init() {
	Load()
}

func BenchmarkMarshalKey(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var key crypto.Key
		r := randomKey()
		R := r.Public().Key()

		{
			s, err := json.Marshal(r.Key())
			if err != nil {
				b.Fatal(err)
			}
			if err := json.Unmarshal(s, &key); err != nil {
				b.Fatal(err)
			}
			if r.Key() != key {
				b.Fatal("unmarshal key not matched")
			}
		}

		{
			s, err := json.Marshal(R)
			if err != nil {
				b.Fatal(err)
			}
			if err := json.Unmarshal(s, &key); err != nil {
				b.Fatal(err)
			}
			if R != key {
				b.Fatal("unmarshal key not matched")
			}
		}
	}
}

func TestPublicKeyMarshal(t *testing.T) {
	assert := assert.New(t)
	for i := 0; i < 10000; i++ {
		p := randomKey().Public().(*PublicKey)
		p1, err := PublicKeyFromKey(p.Key())
		if assert.Nil(err) {
			assert.Equal(p.X, p1.X)
			assert.Equal(p.Y, p1.Y)
		}
	}
}

func TestKey(t *testing.T) {
	assert := assert.New(t)
	seed := make([]byte, 64)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i + 1)
	}
	key := NewPrivateKeyFromSeedOrPanic(seed)
	assert.Equal("000a3c4ec76cbae822affe760cb34a5bc0554fa3cae96171a5b13565a1072e6a93", key.Key().String())
	assert.Equal("028dff4906efc7ad05d04d5d277626144dc3bbb1427b301d2b91e4d8e9847b7142", key.Public().Key().String())

	j, err := key.Key().MarshalJSON()
	assert.Nil(err)
	assert.Equal("\"000a3c4ec76cbae822affe760cb34a5bc0554fa3cae96171a5b13565a1072e6a93\"", string(j))

	var k crypto.Key
	err = k.UnmarshalJSON(j)
	assert.Nil(err)
	priv, err := k.AsPrivateKey()
	assert.Nil(err)
	assert.Equal("000a3c4ec76cbae822affe760cb34a5bc0554fa3cae96171a5b13565a1072e6a93", priv.String())
	assert.Equal("028dff4906efc7ad05d04d5d277626144dc3bbb1427b301d2b91e4d8e9847b7142", priv.Public().Key().String())

	sig, err := key.Sign(seed)
	assert.Nil(err)
	assert.True(key.Public().Verify(seed, sig))
}

func randomKey() *PrivateKey {
	seed := make([]byte, 64)
	rand.Read(seed)
	return NewPrivateKeyFromSeedOrPanic(seed)
}
