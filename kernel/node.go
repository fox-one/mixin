package kernel

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/config"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/kernel/internal/clock"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/mixin/network"
	"github.com/MixinNetwork/mixin/storage"
	"github.com/VictoriaMetrics/fastcache"
)

type Node struct {
	IdForNetwork crypto.Hash
	Signer       common.Address
	Listener     string

	Peer        *network.Peer
	TopoCounter *TopologicalSequence
	SyncPoints  *syncMap

	AllNodesSorted       []*CNode
	AllNodesId           []crypto.Hash
	ConsensusNodes       map[crypto.Hash]*CNode
	SortedConsensusNodes []crypto.Hash
	ConsensusIndex       int
	ConsensusPledging    *CNode
	GraphTimestamp       uint64

	chains *chainsMap

	genesisNodesMap map[crypto.Hash]bool
	genesisNodes    []crypto.Hash
	Epoch           uint64
	startAt         time.Time
	networkId       crypto.Hash
	persistStore    storage.Store
	cacheStore      *fastcache.Cache
	custom          *config.Custom
	configDir       string
	addr            string

	done chan struct{}
	elc  chan struct{}
	mlc  chan struct{}
}

type CNode struct {
	IdForNetwork crypto.Hash
	Signer       common.Address
	Payee        common.Address
	Transaction  crypto.Hash
	Timestamp    uint64
	State        string
}

func SetupNode(custom *config.Custom, persistStore storage.Store, cacheStore *fastcache.Cache, addr string, dir string) (*Node, error) {
	var node = &Node{
		SyncPoints:      &syncMap{mutex: new(sync.RWMutex), m: make(map[crypto.Hash]*network.SyncPoint)},
		ConsensusIndex:  -1,
		chains:          &chainsMap{m: make(map[crypto.Hash]*Chain)},
		genesisNodesMap: make(map[crypto.Hash]bool),
		persistStore:    persistStore,
		cacheStore:      cacheStore,
		custom:          custom,
		configDir:       dir,
		addr:            addr,
		startAt:         clock.Now(),
		done:            make(chan struct{}),
		elc:             make(chan struct{}),
		mlc:             make(chan struct{}),
	}

	node.LoadNodeConfig()

	err := node.LoadGenesis(dir)
	if err != nil {
		return nil, err
	}
	node.TopoCounter = getTopologyCounter(persistStore)

	logger.Println("Validating graph entries...")
	start := clock.Now()
	total, invalid, err := node.persistStore.ValidateGraphEntries(node.networkId, 10)
	if err != nil {
		return nil, err
	} else if invalid > 0 {
		return nil, fmt.Errorf("Validate graph with %d/%d invalid entries\n", invalid, total)
	}
	logger.Printf("Validate graph with %d total entries in %s\n", total, clock.Now().Sub(start).String())

	err = node.LoadConsensusNodes()
	if err != nil {
		return nil, err
	}

	err = node.LoadAllChains(node.persistStore, node.networkId)
	if err != nil {
		return nil, err
	}

	logger.Printf("Listen:\t%s\n", addr)
	logger.Printf("Signer:\t%s\n", node.Signer.String())
	logger.Printf("Network:\t%s\n", node.networkId.String())
	logger.Printf("Node Id:\t%s\n", node.IdForNetwork.String())
	logger.Printf("Topology:\t%d\n", node.TopoCounter.seq)
	return node, nil
}

func (node *Node) LoadNodeConfig() {
	var addr common.Address
	addr.PrivateSpendKey = node.custom.Node.Signer
	addr.PublicSpendKey = addr.PrivateSpendKey.Public()
	addr.PrivateViewKey = addr.PublicSpendKey.DeterministicHashDerive()
	addr.PublicViewKey = addr.PrivateViewKey.Public()
	node.Signer = addr
	node.Listener = node.custom.Network.Listener
}

func (node *Node) ConsensusKeys(timestamp uint64) []crypto.PublicKey {
	if timestamp == 0 {
		timestamp = uint64(clock.Now().UnixNano())
	}

	var keys []crypto.PublicKey
	for _, cn := range node.AllNodesSorted {
		if cn.State != common.NodeStateAccepted {
			continue
		}
		if node.genesisNodesMap[cn.IdForNetwork] || cn.Timestamp+uint64(config.KernelNodeAcceptPeriodMinimum) < timestamp {
			keys = append(keys, cn.Signer.PublicSpendKey)
		}
	}
	return keys
}

func (node *Node) ConsensusThreshold(timestamp uint64) int {
	if timestamp == 0 {
		timestamp = uint64(clock.Now().UnixNano())
	}
	consensusBase := 0
	for _, cn := range node.AllNodesSorted {
		threshold := config.SnapshotReferenceThreshold * config.SnapshotRoundGap
		if threshold > uint64(3*time.Minute) {
			panic("should never be here")
		}
		switch cn.State {
		case common.NodeStatePledging:
			// FIXME the pledge transaction may be broadcasted very late
			// at this situation, the node should be treated as evil
			if config.KernelNodeAcceptPeriodMinimum < time.Hour {
				panic("should never be here")
			}
			threshold = uint64(config.KernelNodeAcceptPeriodMinimum) - threshold*3
			if cn.Timestamp+threshold < timestamp {
				consensusBase++
			}
		case common.NodeStateAccepted:
			if node.genesisNodesMap[cn.IdForNetwork] || cn.Timestamp+threshold < timestamp {
				consensusBase++
			}
		case common.NodeStateResigning:
			consensusBase++
		}
	}
	if consensusBase < len(node.genesisNodes) {
		logger.Debugf("invalid consensus base %d %d %d\n", timestamp, consensusBase, len(node.genesisNodes))
		return 1000
	}
	return consensusBase*2/3 + 1
}

func (node *Node) LoadConsensusNodes() error {
	node.ConsensusPledging = nil
	consensusNodes := make(map[crypto.Hash]*CNode)
	sortedConsensusNodes := make([]crypto.Hash, 0)
	node.AllNodesSorted = node.SortAllNodesByTimestampAndId()
	node.AllNodesId = make([]crypto.Hash, len(node.AllNodesSorted))
	for i, cn := range node.AllNodesSorted {
		node.AllNodesId[i] = cn.IdForNetwork
		if cn.Timestamp == 0 {
			cn.Timestamp = node.Epoch
		}
		logger.Println(cn.IdForNetwork, cn.Signer, cn.State, cn.Timestamp)
		switch cn.State {
		case common.NodeStatePledging:
			node.ConsensusPledging = cn
		case common.NodeStateAccepted:
			consensusNodes[cn.IdForNetwork] = cn
			sortedConsensusNodes = append(sortedConsensusNodes, cn.IdForNetwork)
		case common.NodeStateResigning:
		case common.NodeStateRemoved:
		}
	}
	node.ConsensusNodes = consensusNodes
	node.SortedConsensusNodes = sortedConsensusNodes
	for i, id := range node.SortedConsensusNodes {
		if id == node.IdForNetwork {
			node.ConsensusIndex = i
		}
	}
	return nil
}

func (node *Node) ConsensusRemovedRecently(timestamp uint64) *CNode {
	// FIXME should use all nodes state list, without this hack
	threshold := uint64(config.KernelNodeAcceptPeriodMinimum)
	if timestamp <= threshold {
		return nil
	}
	begin := timestamp - threshold
	end := timestamp + threshold
	for _, cn := range node.AllNodesSorted {
		if cn.Timestamp > end {
			break
		}
		if cn.State != common.NodeStateRemoved {
			continue
		}
		if cn.Timestamp > begin {
			return cn
		}
	}
	return nil
}

func (node *Node) PingNeighborsFromConfig() error {
	node.Peer = network.NewPeer(node, node.IdForNetwork, node.addr, node.custom.Network.GossipNeighbors)

	f, err := ioutil.ReadFile(node.configDir + "/nodes.json")
	if err != nil {
		return err
	}
	var inputs []struct {
		Host string `json:"host"`
	}
	err = json.Unmarshal(f, &inputs)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		if in.Host == node.Listener {
			continue
		}
		node.Peer.PingNeighbor(in.Host)
	}

	return nil
}

func (node *Node) UpdateNeighbors(neighbors []string) error {
	for _, in := range neighbors {
		if in == node.Listener {
			continue
		}
		node.Peer.PingNeighbor(in)
	}
	return nil
}

func (node *Node) ListenNeighbors() error {
	return node.Peer.ListenNeighbors()
}

func (node *Node) NetworkId() crypto.Hash {
	return node.networkId
}

func (node *Node) Uptime() time.Duration {
	return clock.Now().Sub(node.startAt)
}

func (node *Node) GetCacheStore() *fastcache.Cache {
	return node.cacheStore
}

func (node *Node) BuildGraph() []*network.SyncPoint {
	node.chains.RLock()
	defer node.chains.RUnlock()

	points := make([]*network.SyncPoint, 0)
	for _, chain := range node.chains.m {
		if chain.State.CacheRound == nil {
			continue
		}
		f := chain.State.FinalRound
		points = append(points, &network.SyncPoint{
			NodeId: chain.ChainId,
			Hash:   f.Hash,
			Number: f.Number,
		})
	}
	return points
}

func (node *Node) BuildGraphWithPoolInfo() []map[string]interface{} {
	node.chains.RLock()
	defer node.chains.RUnlock()

	points := make([]map[string]interface{}, 0)
	for _, chain := range node.chains.m {
		if chain.State.CacheRound == nil {
			continue
		}
		f := chain.State.FinalRound
		points = append(points, map[string]interface{}{
			"node":  chain.ChainId,
			"round": f.Number,
			"hash":  f.Hash,
			"pool": map[string]int{
				"index": chain.FinalIndex,
				"count": chain.FinalCount,
			},
		})
	}
	return points
}

func (node *Node) BuildAuthenticationMessage() []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(clock.Now().Unix()))
	pubSpendKey := node.Signer.PublicSpendKey.Key()
	data = append(data, pubSpendKey[:]...)
	sig, err := node.Signer.PrivateSpendKey.Sign(data)
	if err != nil {
		panic(err)
	}
	data = append(data, sig[:]...)
	return append(data, []byte(node.Listener)...)
}

func (node *Node) Authenticate(msg []byte) (crypto.Hash, string, error) {
	if len(msg) < 8+len(crypto.Hash{})+len(crypto.Signature{}) {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication message malformated %d", len(msg))
	}
	ts := binary.BigEndian.Uint64(msg[:8])
	if clock.Now().Unix()-int64(ts) > 3 {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication message timeout %d %d", ts, clock.Now().Unix())
	}

	signerPubSpend, err := crypto.PublicKeyFromString(hex.EncodeToString(msg[8 : 8+crypto.KeySize]))
	if err != nil {
		return crypto.Hash{}, "", err
	}
	var signer = common.Address{
		PublicSpendKey: signerPubSpend,
	}
	signer.PublicViewKey = signer.PublicSpendKey.DeterministicHashDerive().Public()
	peerId := signer.Hash().ForNetwork(node.networkId)
	if peerId == node.IdForNetwork {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication invalid consensus peer %s", peerId)
	}
	peer := node.getPeerConsensusNode(peerId)

	if node.custom.Node.ConsensusOnly && peer == nil {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication invalid consensus peer %s", peerId)
	}
	if peer != nil && peer.Signer.Hash() != signer.Hash() {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication invalid consensus peer %s", peerId)
	}

	var sig crypto.Signature
	copy(sig[:], msg[8+crypto.KeySize:8+crypto.KeySize+len(sig)])
	if !signer.PublicSpendKey.Verify(msg[:8+crypto.KeySize], &sig) {
		return crypto.Hash{}, "", fmt.Errorf("peer authentication message signature invalid %s", peerId)
	}

	listener := string(msg[8+crypto.KeySize+len(sig):])
	return peerId, listener, nil
}

func (node *Node) SendTransactionToPeer(peerId, hash crypto.Hash) error {
	tx, _, err := node.persistStore.ReadTransaction(hash)
	if err != nil {
		return err
	}
	if tx == nil {
		tx, err = node.persistStore.CacheGetTransaction(hash)
		if err != nil || tx == nil {
			return err
		}
	}
	return node.Peer.SendTransactionMessage(peerId, tx)
}

func (node *Node) CachePutTransaction(peerId crypto.Hash, tx *common.VersionedTransaction) error {
	return node.persistStore.CachePutTransaction(tx)
}

func (node *Node) ReadAllNodes() []crypto.Hash {
	return node.AllNodesId
}

func (node *Node) ReadSnapshotsSinceTopology(offset, count uint64) ([]*common.SnapshotWithTopologicalOrder, error) {
	return node.persistStore.ReadSnapshotsSinceTopology(offset, count)
}

func (node *Node) ReadSnapshotsForNodeRound(nodeIdWithNetwork crypto.Hash, round uint64) ([]*common.SnapshotWithTopologicalOrder, error) {
	return node.persistStore.ReadSnapshotsForNodeRound(nodeIdWithNetwork, round)
}

func (node *Node) UpdateSyncPoint(peerId crypto.Hash, points []*network.SyncPoint) {
	for _, p := range points {
		if p.NodeId == node.IdForNetwork {
			node.SyncPoints.Set(peerId, p)
		}
	}
}

func (node *Node) CheckBroadcastedToPeers() bool {
	chain := node.GetOrCreateChain(node.IdForNetwork)
	final, count := uint64(0), 1
	threshold := node.ConsensusThreshold(0)
	if r := chain.State.FinalRound; r != nil {
		final = r.Number
	}
	for id := range node.ConsensusNodes {
		remote := node.SyncPoints.Get(id)
		if remote == nil {
			continue
		}
		if remote.Number+1 >= final {
			count += 1
		}
	}
	return count >= threshold
}

func (node *Node) CheckCatchUpWithPeers() bool {
	chain := node.GetOrCreateChain(node.IdForNetwork)
	final, updated := uint64(0), 1
	threshold := node.ConsensusThreshold(0)
	cache := chain.State.CacheRound
	if r := chain.State.FinalRound; r != nil {
		final = r.Number
	}

	for id := range node.ConsensusNodes {
		remote := node.SyncPoints.Get(id)
		if remote == nil {
			continue
		}
		updated = updated + 1
		if remote.Number <= final {
			continue
		}
		if remote.Number > final+1 {
			logger.Verbosef("CheckCatchUpWithPeers local(%d)+1 < remote(%s:%d)\n", final, id, remote.Number)
			return false
		}
		if cache == nil {
			logger.Verbosef("CheckCatchUpWithPeers local cache nil\n")
			return false
		}
		cf := cache.asFinal()
		if cf == nil {
			logger.Verbosef("CheckCatchUpWithPeers local cache empty\n")
			return false
		}
		if cf.Hash != remote.Hash {
			logger.Verbosef("CheckCatchUpWithPeers local(%s) != remote(%s)\n", cf.Hash, remote.Hash)
			return false
		}
		if now := uint64(clock.Now().UnixNano()); cf.Start+config.SnapshotRoundGap*100 > now {
			logger.Verbosef("CheckCatchUpWithPeers local start(%d)+%d > now(%d)\n", cf.Start, config.SnapshotRoundGap*100, now)
			return false
		}
	}

	if updated < threshold {
		logger.Verbosef("CheckCatchUpWithPeers updated(%d) < threshold(%d)\n", updated, threshold)
	}
	return updated >= threshold
}

type syncMap struct {
	mutex *sync.RWMutex
	m     map[crypto.Hash]*network.SyncPoint
}

func (s *syncMap) Set(k crypto.Hash, p *network.SyncPoint) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.m[k] = p
}

func (s *syncMap) Get(k crypto.Hash) *network.SyncPoint {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.m[k]
}
