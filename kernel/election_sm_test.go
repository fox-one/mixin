// +build sm custom_alg

package kernel

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/fox-one/mixin/common"
	"github.com/fox-one/mixin/config"
	"github.com/fox-one/mixin/crypto"
	"github.com/fox-one/mixin/crypto/sm"
	"github.com/fox-one/mixin/storage"
	"github.com/stretchr/testify/assert"
)

func init() {
	sm.Load()
}

func TestNodeRemovePossibility(t *testing.T) {
	assert := assert.New(t)

	root, err := ioutil.TempDir("", "mixin-election-test")
	assert.Nil(err)
	defer os.RemoveAll(root)

	node := setupTestNode(assert, root)
	assert.NotNil(node)

	now, err := time.Parse(time.RFC3339, "2020-02-09T15:35:13Z")
	assert.Nil(err)
	candi, err := node.checkRemovePossibility(node.IdForNetwork, uint64(now.UnixNano()))
	assert.Nil(candi)
	assert.NotNil(err)
	assert.Contains(err.Error(), "all old nodes removed")

	now, err = time.Parse(time.RFC3339, "2020-02-27T17:00:00Z")
	assert.Nil(err)
	candi, err = node.checkRemovePossibility(node.IdForNetwork, uint64(now.UnixNano()))
	assert.Nil(candi)
	assert.NotNil(err)
	assert.Contains(err.Error(), "all old nodes removed")

	now, err = time.Parse(time.RFC3339, "2020-02-28T00:00:00Z")
	assert.Nil(err)
	candi, err = node.checkRemovePossibility(node.IdForNetwork, uint64(now.UnixNano()))
	assert.Nil(candi)
	assert.NotNil(err)
	assert.Contains(err.Error(), "invalid node remove hour")

	now, err = time.Parse(time.RFC3339, "2020-02-28T17:00:00Z")
	assert.Nil(err)
	candi, err = node.checkRemovePossibility(node.IdForNetwork, uint64(now.UnixNano()))
	assert.Nil(err)
	assert.NotNil(candi)
	assert.Equal("04559ee5e1f459e973ba6988e51eb12e70dedc61971cc1f3e4bcfd6589073c70", candi.IdForNetwork(node.networkId).String())
	assert.Nil(node.ConsensusRemovedRecently(uint64(now.UnixNano())))

	tx, err := node.buildRemoveTransaction(candi)
	assert.Nil(err)
	assert.NotNil(tx)
	assert.Equal("f2d395310f0c0a55580a2cea219a5c329442840e4db65317b39243187ed697f9", tx.PayloadHash().String())
	assert.Equal(common.XINAssetId, tx.Asset)
	assert.Equal(pledgeAmount(0), tx.Outputs[0].Amount)
	assert.Equal("fffe01", tx.Outputs[0].Script.String())
	assert.Equal(uint8(common.OutputTypeNodeRemove), tx.Outputs[0].Type)
	assert.Equal(uint8(common.TransactionTypeNodeRemove), tx.TransactionType())
	assert.Len(tx.Outputs[0].Keys, 1)

	err = tx.SignInput(node.persistStore, 0, []common.Address{node.Signer})
	assert.NotNil(err)
	assert.Contains(err.Error(), "invalid key for the input")
	err = tx.Validate(node.persistStore)
	assert.Nil(err)

	payee, err := common.NewAddressFromString("XIN8EyxiMgziizn5LTzYuCbbTtqJeLvWMEazgNWX2ucKc4o7EUFzDyZiGxbiQGbTcfFLYXYZpZVeRj7xDGbBz8WSVYb86es1gx")
	assert.Nil(err)
	mask, err := tx.Outputs[0].Mask.AsPublicKey()
	assert.Nil(err)
	ghost, err := tx.Outputs[0].Keys[0].AsPublicKey()
	assert.Nil(err)
	view := payee.PublicSpendKey.DeterministicHashDerive()
	assert.Equal(payee.PublicSpendKey.String(), crypto.ViewGhostOutputKey(mask, ghost, view, 0).String())
}

var configData = []byte(`[node]
signer-key = "00068fd928a48d08d930c50c7d762403ce4380cbb608e5cf95fc864efcd5b3b209"
consensus-only = true
memory-cache-size = 16
cache-ttl = 7200
ring-cache-size = 4096
ring-final-size = 16384
[network]
listener = "mixin-node.example.com:7239"`)

func setupTestNode(assert *assert.Assertions, dir string) *Node {
	err := ioutil.WriteFile(dir+"/config.toml", configData, 0644)
	assert.Nil(err)

	data, err := ioutil.ReadFile("../config/genesis.example.sm.json")
	assert.Nil(err)
	err = ioutil.WriteFile(dir+"/genesis.json", data, 0644)
	assert.Nil(err)

	data, err = ioutil.ReadFile("../config/nodes.json")
	assert.Nil(err)
	err = ioutil.WriteFile(dir+"/nodes.json", data, 0644)
	assert.Nil(err)

	err = config.Initialize(dir + "/config.toml")
	assert.Nil(err)
	cache := fastcache.New(16 * 1024 * 1024)
	store, err := storage.NewBadgerStore(dir)
	assert.Nil(err)
	assert.NotNil(store)
	node, err := SetupNode(store, cache, ":7239", dir)
	assert.Nil(err)
	return node
}
