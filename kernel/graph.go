package kernel

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/fox-one/mixin/common"
	"github.com/fox-one/mixin/config"
	"github.com/fox-one/mixin/crypto"
	"github.com/fox-one/mixin/logger"
)

func (chain *Chain) startNewRound(s *common.Snapshot, cache *CacheRound, allowDummy bool) (*FinalRound, bool, error) {
	if chain.ChainId != cache.NodeId {
		panic("should never be here")
	}
	if chain.ChainId != s.NodeId {
		panic("should never be here")
	}
	if s.RoundNumber != cache.Number+1 {
		panic("should never be here")
	}
	final := cache.asFinal()
	if final == nil {
		return nil, false, fmt.Errorf("self cache snapshots not collected yet %s %d", s.NodeId, s.RoundNumber)
	}
	if s.References.Self != final.Hash {
		return nil, false, fmt.Errorf("self cache snapshots not match yet %s %s", s.NodeId, s.References.Self)
	}

	finalized := chain.node.verifyFinalization(s)
	external, err := chain.persistStore.ReadRound(s.References.External)
	if err != nil {
		return nil, false, err
	}
	if external == nil && finalized && allowDummy {
		return final, true, nil
	}
	if external == nil {
		return nil, false, fmt.Errorf("external round %s not collected yet", s.References.External)
	}
	if final.NodeId == external.NodeId {
		return nil, false, nil
	}
	if !chain.node.genesisNodesMap[external.NodeId] && external.Number < 7+config.SnapshotReferenceThreshold {
		return nil, false, nil
	}
	if !finalized {
		externalChain := chain.node.GetOrCreateChain(external.NodeId)
		if external.Number+config.SnapshotSyncRoundThreshold < externalChain.State.FinalRound.Number {
			return nil, false, fmt.Errorf("external reference %s too early %d %d", s.References.External, external.Number, externalChain.State.FinalRound.Number)
		}
		if external.Timestamp > s.Timestamp {
			return nil, false, fmt.Errorf("external reference later than snapshot time %f", time.Duration(external.Timestamp-s.Timestamp).Seconds())
		}
		threshold := external.Timestamp + config.SnapshotReferenceThreshold*config.SnapshotRoundGap*64
		best, err := chain.determinBestRound(s.Timestamp, external.NodeId)
		if err != nil {
			return nil, false, fmt.Errorf("external reference %s invalid %s", s.References.External, err)
		} else if best != nil && threshold < best.Start {
			return nil, false, fmt.Errorf("external reference %s too early %s:%d %f", s.References.External, best.NodeId, best.Number, time.Duration(best.Start-threshold).Seconds())
		}
	}
	if external.Number < chain.State.RoundLinks[external.NodeId] {
		return nil, false, err
	}
	link, err := chain.persistStore.ReadLink(s.NodeId, external.NodeId)
	if err != nil {
		return nil, false, err
	}
	if link != chain.State.RoundLinks[external.NodeId] {
		panic(fmt.Errorf("should never be here %s=>%s %d %d", chain.ChainId, external.NodeId, link, chain.State.RoundLinks[external.NodeId]))
	}
	chain.State.RoundLinks[external.NodeId] = external.Number

	return final, false, err
}

func (chain *Chain) updateEmptyHeadRound(m *CosiAction, cache *CacheRound, s *common.Snapshot) (bool, error) {
	if len(cache.Snapshots) != 0 {
		logger.Verbosef("ERROR cosiHandleFinalization malformated head round references not empty %s %v %d\n", m.PeerId, s, len(cache.Snapshots))
		return false, nil
	}
	if s.References.Self != cache.References.Self {
		logger.Verbosef("ERROR cosiHandleFinalization malformated head round references self diff %s %v %v\n", m.PeerId, s, cache.References)
		return false, nil
	}
	external, err := chain.persistStore.ReadRound(s.References.External)
	if err != nil || external == nil {
		logger.Verbosef("ERROR cosiHandleFinalization head round references external not ready yet %s %v %v\n", m.PeerId, s, cache.References)
		return false, err
	}
	link, err := chain.persistStore.ReadLink(cache.NodeId, external.NodeId)
	if err != nil || external.Number < link {
		return false, err
	}
	chain.State.RoundLinks[external.NodeId] = external.Number
	return true, nil
}

func (chain *Chain) assignNewGraphRound(final *FinalRound, cache *CacheRound) {
	if chain.ChainId != cache.NodeId {
		panic("should never be here")
	}
	if chain.ChainId != final.NodeId {
		panic("should never be here")
	}
	if final.Number+1 != cache.Number {
		panic("should never be here")
	}
	if final.NodeId != cache.NodeId {
		panic(fmt.Errorf("should never be here %s %s", final.NodeId, cache.NodeId))
	}

	chain.State.CacheRound = cache
	chain.State.FinalRound = final
	if final.End > chain.node.GraphTimestamp {
		chain.node.GraphTimestamp = final.End
	}

	rounds := chain.State.RoundHistory
	if len(rounds) == 0 && final.Number == 0 {
		logger.Printf("assign the first round %s %s\n", chain.node.IdForNetwork, chain.ChainId)
	} else if n := rounds[len(rounds)-1].Number; n == final.Number {
		return
	} else if n+1 != final.Number {
		panic(fmt.Errorf("should never be here %s %d %d", final.NodeId, final.Number, n))
	}

	rounds = append(rounds, final.Copy())
	chain.StepForward()

	threshold := config.SnapshotReferenceThreshold * config.SnapshotRoundGap * 64
	if rounds[0].Start+threshold > final.Start && len(rounds) <= config.SnapshotReferenceThreshold {
		chain.State.RoundHistory = rounds
		return
	}
	newRounds := make([]*FinalRound, 0)
	for _, r := range rounds {
		if r.Start+threshold <= final.Start {
			continue
		}
		newRounds = append(newRounds, r)
	}
	if rc := len(newRounds) - config.SnapshotReferenceThreshold; rc > 0 {
		newRounds = newRounds[rc:]
	}
	chain.State.RoundHistory = newRounds
}

func (node *Node) CacheVerify(snap crypto.Hash, sig crypto.Signature, pub crypto.PublicKey) bool {
	pubKey := pub.Key()
	key := append(snap[:], sig[:]...)
	key = append(key, pubKey[:]...)
	value := node.cacheStore.Get(nil, key)
	if len(value) == 1 {
		return value[0] == byte(1)
	}
	valid := pub.Verify(snap[:], &sig)
	if valid {
		node.cacheStore.Set(key, []byte{1})
	} else {
		node.cacheStore.Set(key, []byte{0})
	}
	return valid
}

func (node *Node) CacheVerifyCosi(snap crypto.Hash, sig *crypto.CosiSignature, publics []crypto.PublicKey, threshold int) bool {
	if snap.String() == "b3ea56de6124ad2f3ad1d48f2aff8338b761e62bcde6f2f0acba63a32dd8eecc" &&
		sig.String() == "dbb0347be24ecb8de3d66631d347fde724ff92e22e1f45deeb8b5d843fd62da39ca8e39de9f35f1e0f7336d4686917983470c098edc91f456d577fb18069620f000000003fdfe712" {
		// FIXME this is a hack to fix the large round gap around node remove snapshot
		// and a bug in too recent external reference, e.g. bare final round
		return true
	}
	key := common.MsgpackMarshalPanic(sig)
	key = append(snap[:], key...)
	for _, pub := range publics {
		pubKey := pub.Key()
		key = append(key, pubKey[:]...)
	}
	tbuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tbuf, uint64(threshold))
	key = append(key, tbuf...)
	binary.BigEndian.PutUint64(tbuf, sig.Mask)
	key = append(key, tbuf...)
	value := node.cacheStore.Get(nil, key)
	if len(value) == 1 {
		return value[0] == byte(1)
	}
	if !sig.FullVerify(publics, threshold, snap[:]) {
		logger.Verbosef("CacheVerifyCosi(%s, %d, %d) Failed\n", snap, len(publics), threshold)
		node.cacheStore.Set(key, []byte{0})
	} else {
		node.cacheStore.Set(key, []byte{1})
	}
	return true
}

func (node *Node) checkInitialAcceptSnapshotWeak(s *common.Snapshot) bool {
	pledge := node.ConsensusPledging
	if pledge == nil {
		return false
	}
	if node.genesisNodesMap[s.NodeId] {
		return false
	}
	if s.NodeId != pledge.IdForNetwork {
		return false
	}
	return s.RoundNumber == 0
}

func (node *Node) checkInitialAcceptSnapshot(s *common.Snapshot, tx *common.VersionedTransaction) bool {
	chain := node.GetOrCreateChain(s.NodeId)
	if chain.State.FinalRound != nil {
		return false
	}
	return node.checkInitialAcceptSnapshotWeak(s) && tx.TransactionType() == common.TransactionTypeNodeAccept
}

func (chain *Chain) queueActionOrPanic(m *CosiAction) error {
	if chain.ChainId != m.PeerId {
		panic("should never be here")
	}
	err := chain.AppendCosiAction(m)
	if err != nil {
		panic(err)
	}
	return nil
}

func (chain *Chain) clearAndQueueSnapshotOrPanic(s *common.Snapshot) error {
	if chain.ChainId != s.NodeId {
		panic("should never be here")
	}
	delete(chain.CosiVerifiers, s.Hash)
	delete(chain.CosiAggregators, s.Hash)
	delete(chain.CosiAggregators, s.Transaction)
	return chain.AppendSelfEmpty(&common.Snapshot{
		Version:     common.SnapshotVersion,
		NodeId:      s.NodeId,
		Transaction: s.Transaction,
	})
}

func (node *Node) verifyFinalization(s *common.Snapshot) bool {
	if s.Version == 0 {
		return node.legacyVerifyFinalization(s.Timestamp, s.Signatures)
	}
	if s.Version != common.SnapshotVersion || s.Signature == nil {
		return false
	}
	publics := node.ConsensusKeys(s.Timestamp)
	if node.checkInitialAcceptSnapshotWeak(s) {
		publics = append(publics, node.ConsensusPledging.Signer.PublicSpendKey)
	}
	base := node.ConsensusThreshold(s.Timestamp)
	if node.CacheVerifyCosi(s.Hash, s.Signature, publics, base) {
		return true
	}
	if rr := node.ConsensusRemovedRecently(s.Timestamp); rr != nil {
		for i := range publics {
			pwr := append([]crypto.PublicKey{}, publics[:i]...)
			pwr = append(pwr, rr.Signer.PublicSpendKey)
			pwr = append(pwr, publics[i:]...)
			if node.CacheVerifyCosi(s.Hash, s.Signature, pwr, base) {
				return true
			}
		}
	}
	return false
}

func (node *Node) legacyVerifyFinalization(timestamp uint64, sigs []*crypto.Signature) bool {
	return len(sigs) >= node.ConsensusThreshold(timestamp)
}
