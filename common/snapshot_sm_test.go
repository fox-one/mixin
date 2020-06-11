// +build sm,custom_alg

package common

import (
	"crypto/rand"
	"testing"

	"github.com/fox-one/mixin/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSnapshot(t *testing.T) {
	assert := assert.New(t)

	genesisHash := crypto.Hash{}
	script := Script{OperatorCmp, OperatorSum, 2}
	accounts := make([]Address, 0)
	for i := 0; i < 3; i++ {
		accounts = append(accounts, randomAccount())
	}

	tx := NewTransaction(XINAssetId)
	tx.AddInput(genesisHash, 0)
	tx.AddInput(genesisHash, 1)
	tx.AddRandomScriptOutput(accounts, script, NewInteger(20000))

	s := &Snapshot{Version: SnapshotVersion}
	assert.Len(s.VersionedPayload(), 133)
	assert.Equal("6c37e084101b99bc3cf42c061797024a05be6af439d67fb5eeef6cd7b0fbc1b9", s.PayloadHash().String())

	s = &Snapshot{}
	assert.Len(s.Signatures, 0)
	assert.Len(s.VersionedPayload(), 136)
	assert.Equal("c9b2b807970e28c0735301c030b2ef516c8ed832a4fc4b848dbbf77f619e5918", s.PayloadHash().String())

	seed := make([]byte, 64)
	rand.Read(seed)
	key := crypto.PrivateKeyFromSeed(seed)
	rand.Read(seed)
	pub := crypto.PrivateKeyFromSeed(seed).Public()
	sign(s, key)
	assert.Len(s.Signatures, 1)
	assert.Len(s.VersionedPayload(), 136)
	assert.False(checkSignature(s, pub))
	assert.True(checkSignature(s, key.Public()))
	sign(s, key)
	assert.Len(s.Signatures, 2)
	assert.Len(s.VersionedPayload(), 136)
	assert.False(checkSignature(s, pub))
	assert.True(checkSignature(s, key.Public()))
}

func checkSignature(s *Snapshot, pub crypto.PublicKey) bool {
	msg := s.PayloadHash()
	for _, sig := range s.Signatures {
		if !pub.Verify(msg[:], sig) {
			return false
		}
	}
	return true
}

func sign(s *Snapshot, key crypto.PrivateKey) {
	msg := s.PayloadHash()
	sig, _ := key.Sign(msg[:])
	for _, o := range s.Signatures {
		if o.String() == sig.String() {
			return
		}
	}
	s.Signatures = append(s.Signatures, sig)
}
