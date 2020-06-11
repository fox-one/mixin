// +build sm,custom_alg

package sm

import (
	"testing"

	"github.com/fox-one/mixin/crypto"
	"github.com/stretchr/testify/assert"
)

func TestCosi(t *testing.T) {
	assert := assert.New(t)

	var (
		raw = []byte("just a test")

		privates   = make(map[int]crypto.PrivateKey, 20)
		publics    = make(map[int]crypto.PublicKey, 20)
		publicArr  = make([]crypto.PublicKey, 20)
		commitents = make(map[int]*crypto.Commitment, 20)
	)

	for i := 0; i < 20; i++ {
		var (
			p = randomKey()
			P = p.Public()
		)
		commitents[i] = &crypto.Commitment{}
		privates[i] = p
		publics[i] = P
		publicArr[i] = P
	}

	cosi, err := crypto.CosiAggregateCommitments(commitents)
	assert.Nil(err)

	{
		for i, p := range privates {
			sig, err := p.Sign(raw)
			assert.Nil(err)
			assert.True(publics[i].Verify(raw, sig))
			assert.Nil(cosi.AggregateSignature(i, sig))
		}

		assert.Equal(20, len(cosi.Signatures))
		assert.True(cosi.FullVerify(publicArr, len(publicArr), raw))
	}
}
