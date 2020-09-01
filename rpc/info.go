package rpc

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/fox-one/mixin/common"
	"github.com/fox-one/mixin/config"
	"github.com/fox-one/mixin/crypto"
	"github.com/fox-one/mixin/kernel"
	"github.com/fox-one/mixin/storage"
)

func getConsensusKeys(node *kernel.Node, params []interface{}) ([]*crypto.Key, error) {
	if len(params) != 1 {
		return nil, errors.New("invalid params count")
	}
	timestamp, err := strconv.ParseUint(fmt.Sprint(params[0]), 10, 64)
	if err != nil {
		return nil, err
	}
	pubKeys := node.ConsensusKeys(timestamp)
	keys := make([]*crypto.Key, len(pubKeys))
	for idx, P := range pubKeys {
		k := P.Key()
		keys[idx] = &k
	}
	return keys, nil
}

func getInfo(store storage.Store, node *kernel.Node) (map[string]interface{}, error) {
	info := map[string]interface{}{
		"network":   node.NetworkId(),
		"node":      node.IdForNetwork,
		"version":   config.BuildVersion,
		"uptime":    node.Uptime().String(),
		"epoch":     time.Unix(0, int64(node.Epoch)),
		"timestamp": time.Unix(0, int64(node.GraphTimestamp)),
	}
	pool, err := node.PoolSize()
	if err != nil {
		return info, err
	}
	md, err := store.ReadLastMintDistribution(common.MintGroupKernelNode)
	if err != nil {
		return info, err
	}
	info["mint"] = map[string]interface{}{
		"pool":  pool,
		"batch": md.Batch,
	}
	cacheMap, finalMap, err := kernel.LoadRoundGraph(store, node.NetworkId(), node.IdForNetwork)
	if err != nil {
		return info, err
	}
	cacheGraph := make(map[string]interface{})
	for n, r := range cacheMap {
		for i := range r.Snapshots {
			r.Snapshots[i].Signatures = nil
		}
		cacheGraph[n.String()] = map[string]interface{}{
			"node":       r.NodeId.String(),
			"round":      r.Number,
			"timestamp":  r.Timestamp,
			"snapshots":  r.Snapshots,
			"references": r.References,
		}
	}
	finalGraph := make(map[string]interface{})
	for n, r := range finalMap {
		finalGraph[n.String()] = map[string]interface{}{
			"node":  r.NodeId.String(),
			"round": r.Number,
			"start": r.Start,
			"end":   r.End,
			"hash":  r.Hash.String(),
		}
	}

	nodes := make([]map[string]interface{}, 0)
	for id, n := range node.ConsensusNodes {
		nodes = append(nodes, map[string]interface{}{
			"node":        id,
			"signer":      n.Signer.String(),
			"payee":       n.Payee.String(),
			"state":       n.State,
			"timestamp":   n.Timestamp,
			"transaction": n.Transaction.String(),
		})
	}
	if n := node.ConsensusPledging; n != nil {
		nodes = append(nodes, map[string]interface{}{
			"node":      n.IdForNetwork,
			"signer":    n.Signer.String(),
			"payee":     n.Payee.String(),
			"state":     n.State,
			"timestamp": n.Timestamp,
		})
	}
	info["graph"] = map[string]interface{}{
		"consensus": nodes,
		"cache":     cacheGraph,
		"final":     finalGraph,
		"topology":  node.TopologicalOrder(),
		"sps":       node.SPS(),
	}
	caches, finals := node.PoolInfo()
	info["queue"] = map[string]interface{}{
		"finals": finals,
		"caches": caches,
	}
	return info, nil
}

func dumpGraphHead(node *kernel.Node, params []interface{}) ([]map[string]interface{}, error) {
	rounds := node.BuildGraphWithPoolInfo()
	sort.Slice(rounds, func(i, j int) bool { return fmt.Sprint(rounds[i]["node"]) < fmt.Sprint(rounds[j]["node"]) })
	return rounds, nil
}
