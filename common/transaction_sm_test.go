// +build sm,custom_alg

package common

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/fox-one/mixin/crypto"
	"github.com/stretchr/testify/assert"
)

func TestDepositTransaction(t *testing.T) {
	assert := assert.New(t)

	var (
		chainID  = crypto.NewHash([]byte("c6d0c728-2624-429b-8e0d-d9d19b6592fa"))
		assetID  = crypto.NewHash([]byte("815b0b1a-2764-3736-8faa-42d694fa620a"))
		assetKey = "815b0b1a-2764-3736-8faa-42d694fa620a"
		amount   = NewIntegerFromString("12345.54321")
	)

	accounts := make([]Address, 0)
	for i := 0; i < 3; i++ {
		seed := make([]byte, 64)
		seed[i] = byte(i)
		accounts = append(accounts, NewAddressFromSeed(seed))
	}

	seed := make([]byte, 64)
	rand.Read(seed)
	store := storeImpl{seed: seed, accounts: accounts}

	tx := NewTransaction(assetID)
	deposit := DepositData{
		TransactionHash: "c5945a8571fc84cd6850b26b5771d76311ed56957a04e993927de07b83f07c91",
		Chain:           chainID,
		AssetKey:        assetKey,
		Amount:          amount,
	}
	tx.AddDepositInput(&deposit)

	rand.Read(seed)
	tx.AddScriptOutput(accounts, NewThresholdScript(1), amount, seed)

	signed := tx.AsLatestVersion()
	err := signed.SignInput(nil, 0, accounts[:1])
	assert.Nil(err)

	err = signed.Validate(store)
	assert.Nil(err)
}

func TestTransaction(t *testing.T) {
	assert := assert.New(t)

	accounts := make([]Address, 0)
	for i := 0; i < 3; i++ {
		seed := make([]byte, 64)
		seed[i] = byte(i)
		accounts = append(accounts, NewAddressFromSeed(seed))
	}

	seed := make([]byte, 64)
	rand.Read(seed)
	genesisHash := crypto.Hash{}
	script := Script{OperatorCmp, OperatorSum, 2}
	store := storeImpl{seed: seed, accounts: accounts}

	ver := NewTransaction(XINAssetId).AsLatestVersion()
	assert.Equal("c5d5b44ffba61aa63fa50f0df737b97fa265375e78670a165850bfee68947b30", ver.PayloadHash().String())
	ver.AddInput(genesisHash, 0)
	assert.Equal("f5d928567afbc7594cd441e31af2a2def794c74247f97602970c5918a216e578", ver.PayloadHash().String())
	ver.AddInput(genesisHash, 1)
	assert.Equal("5fe7efbb559ba91c6bb0093bd606b2602458f648d14f689974637f9d9d25602c", ver.PayloadHash().String())
	ver.Outputs = append(ver.Outputs, &Output{Type: OutputTypeScript, Amount: NewInteger(10000), Script: script, Mask: crypto.NewPrivateKeyFromSeed(bytes.Repeat([]byte{1}, 64)).Key()})
	assert.Equal("7c9d1c4e98e30ae5aa599686c1fbeb7bcccf1991bb29010112332e68d304f0e1", ver.PayloadHash().String())
	ver.AddScriptOutput(accounts, script, NewInteger(10000), bytes.Repeat([]byte{1}, 64))
	assert.Equal("a9379c1dbd902b572d630d59bb5185ac836e3b05399ef3d492eb7e0ec92b4d3a", ver.PayloadHash().String())

	pm := ver.Marshal()
	assert.Equal(493, len(pm))
	assert.Equal("86a756657273696f6e01a54173736574c420456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692a6496e707574739285a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657800a747656e65736973c0a74465706f736974c0a44d696e74c085a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657801a747656e65736973c0a74465706f736974c0a44d696e74c0a74f7574707574739285a45479706500a6416d6f756e74c70500e8d4a51000a44b657973c0a6536372697074c403fffe02a44d61736bc42100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe785a45479706500a6416d6f756e74c70500e8d4a51000a44b65797393c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126ea6536372697074c403fffe02a44d61736bc42103b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474a54578747261c0aa5369676e617475726573c0", hex.EncodeToString(pm))
	cm := ver.CompressMarshal()
	assert.Equal(283, len(cm))
	assert.Equal("0000000028b52ffd63c118533ced004d0800240d456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692921000022100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe793c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126e03b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474c012fc7abb539ea7858ccacb478d26580b037a9017c4e0d14e7ff903b7249d5626f873ebbe74876507f8dcd9eb2d1b7fd9f5a294dd01", hex.EncodeToString(cm))
	ver, err := DecompressUnmarshalVersionedTransaction(cm)
	assert.Nil(err)
	pm = ver.Marshal()
	assert.Equal(493, len(pm))
	assert.Equal("86a756657273696f6e01a54173736574c420456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692a6496e707574739285a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657800a747656e65736973c0a74465706f736974c0a44d696e74c085a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657801a747656e65736973c0a74465706f736974c0a44d696e74c0a74f7574707574739285a45479706500a6416d6f756e74c70500e8d4a51000a44b657973c0a6536372697074c403fffe02a44d61736bc42100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe785a45479706500a6416d6f756e74c70500e8d4a51000a44b65797393c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126ea6536372697074c403fffe02a44d61736bc42103b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474a54578747261c0aa5369676e617475726573c0", hex.EncodeToString(pm))
	ver, err = DecompressUnmarshalVersionedTransaction(pm)
	assert.Nil(err)
	pm = ver.Marshal()
	assert.Equal(493, len(pm))
	assert.Equal("86a756657273696f6e01a54173736574c420456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692a6496e707574739285a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657800a747656e65736973c0a74465706f736974c0a44d696e74c085a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657801a747656e65736973c0a74465706f736974c0a44d696e74c0a74f7574707574739285a45479706500a6416d6f756e74c70500e8d4a51000a44b657973c0a6536372697074c403fffe02a44d61736bc42100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe785a45479706500a6416d6f756e74c70500e8d4a51000a44b65797393c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126ea6536372697074c403fffe02a44d61736bc42103b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474a54578747261c0aa5369676e617475726573c0", hex.EncodeToString(pm))
	cm, err = hex.DecodeString("0000000028b52ffd63c118533ced004d0800240d456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692921000022100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe793c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126e03b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474c012fc7abb539ea7858ccacb478d26580b037a9017c4e0d14e7ff903b7249d5626f873ebbe74876507f8dcd9eb2d1b7fd9f5a294dd01")
	assert.Nil(err)
	ver, err = DecompressUnmarshalVersionedTransaction(cm)
	assert.Nil(err)
	pm = ver.Marshal()
	assert.Equal(493, len(pm))
	assert.Equal("86a756657273696f6e01a54173736574c420456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692a6496e707574739285a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657800a747656e65736973c0a74465706f736974c0a44d696e74c085a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657801a747656e65736973c0a74465706f736974c0a44d696e74c0a74f7574707574739285a45479706500a6416d6f756e74c70500e8d4a51000a44b657973c0a6536372697074c403fffe02a44d61736bc42100481961030651625ebe819d69a104bd600a50a92091da085ac62c1dc48b73bbe785a45479706500a6416d6f756e74c70500e8d4a51000a44b65797393c421030adb988ab4e51f99c86bc369c7a00cb856887d6f905c833c2fc5523c5b9088e9c42103c4ce9e4b82604c6acc7d4e994d1ead17074c9924766cfc4fe8ca07533bdc7509c421025d1da598bdcd4fc593e47ba5c8235736ba55b1f59278a05a895c932e51e7126ea6536372697074c403fffe02a44d61736bc42103b019b1d3509a2930d86e053dce84972446d03bccdac53be663030914679d4474a54578747261c0aa5369676e617475726573c0", hex.EncodeToString(pm))
	cm, err = hex.DecodeString("0000000028b52ffd63c118533ced005d0800140d456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e69292100002214fe2a684e0e6c5e370ca0d89f5e2cb0da1e2ecd4028fa2d395fbca4e33f2580593c42103b52a659f098ab2021a319f3c485eba6a88f99f1dc2884696ee9c057447c5e946c421026bd5c45d54a36bd642c35b4929b81d0059b6503ee462cb2e63d805a059712afec4210285f1ba5d918e170f44bc456bdfd23023370701e2785b560b499aea4e12a91354021f5db9c351ccfd22d74760ef93ed1fab16e62ca1c4d827a6a1b9eb2cb825dc22c013fc7abb539ea7858ccacb4731e946292ecf6508f4744610c313e9fef007d392f41499e0cfabfbd61d961de07367afa32cfc75d78b52f004")
	assert.Nil(err)
	ver, err = DecompressUnmarshalVersionedTransaction(cm)
	assert.Nil(err)

	pm = ver.Marshal()
	assert.Equal(493, len(pm))
	assert.Equal("86a756657273696f6e01a54173736574c420456bbf84b42c3bd09b0e63e9d176d21e281f7d4e6977363e5443333474e0e692a6496e707574739285a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657800a747656e65736973c0a74465706f736974c0a44d696e74c085a448617368c4200000000000000000000000000000000000000000000000000000000000000000a5496e64657801a747656e65736973c0a74465706f736974c0a44d696e74c0a74f7574707574739285a45479706500a6416d6f756e74c70500e8d4a51000a44b657973c0a6536372697074c403fffe02a44d61736bc4214fe2a684e0e6c5e370ca0d89f5e2cb0da1e2ecd4028fa2d395fbca4e33f258050085a45479706500a6416d6f756e74c70500e8d4a51000a44b65797393c42103b52a659f098ab2021a319f3c485eba6a88f99f1dc2884696ee9c057447c5e946c421026bd5c45d54a36bd642c35b4929b81d0059b6503ee462cb2e63d805a059712afec4210285f1ba5d918e170f44bc456bdfd23023370701e2785b560b499aea4e12a91354a6536372697074c403fffe02a44d61736bc421021f5db9c351ccfd22d74760ef93ed1fab16e62ca1c4d827a6a1b9eb2cb825dc22a54578747261c0aa5369676e617475726573c0", hex.EncodeToString(pm))

	for i := range ver.Inputs {
		err := ver.SignInput(store, i, accounts)
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid key for the input")
	}
	err = ver.Validate(store)
	assert.NotNil(err)
	assert.Contains(err.Error(), "invalid tx signature number")

	for i := range ver.Inputs {
		err := ver.SignInput(store, i, accounts[0:i+1])
		assert.Nil(err)
	}
	err = ver.Validate(store)
	assert.Nil(err)

	outputs := ver.ViewGhostKey(accounts[1].PrivateViewKey)
	assert.Len(outputs, 2)
	assert.Equal(outputs[1].Keys[1].String(), accounts[1].PublicSpendKey.String())
	outputs = ver.ViewGhostKey(accounts[1].PrivateSpendKey)
	assert.Len(outputs, 2)
	assert.NotEqual(outputs[1].Keys[1].String(), accounts[1].PublicSpendKey.String())
	assert.NotEqual(outputs[1].Keys[1].String(), accounts[1].PublicViewKey.String())
}

type storeImpl struct {
	seed     []byte
	accounts []Address
}

func (store storeImpl) ReadUTXO(hash crypto.Hash, index int) (*UTXOWithLock, error) {
	genesisMaskr := crypto.NewPrivateKeyFromSeed(store.seed)
	genesisMaskR := genesisMaskr.Public()

	in := Input{
		Hash:  hash,
		Index: index,
	}
	out := Output{
		Type:   OutputTypeScript,
		Amount: NewInteger(10000),
		Script: Script{OperatorCmp, OperatorSum, uint8(index + 1)},
		Mask:   genesisMaskR.Key(),
	}
	utxo := &UTXOWithLock{
		UTXO: UTXO{
			Input:  in,
			Output: out,
			Asset:  XINAssetId,
		},
	}

	for i := 0; i <= index; i++ {
		key := crypto.DeriveGhostPublicKey(genesisMaskr, store.accounts[i].PublicViewKey, store.accounts[i].PublicSpendKey, uint64(index)).Key()
		utxo.Keys = append(utxo.Keys, key)
	}
	return utxo, nil
}

func (store storeImpl) CheckGhost(key crypto.Key) (bool, error) {
	return false, nil
}

func (store storeImpl) LockUTXO(hash crypto.Hash, index int, tx crypto.Hash, fork bool) error {
	return nil
}

func (store storeImpl) ReadDomains() []Domain {
	return []Domain{Domain{store.accounts[0]}}
}

func (store storeImpl) ReadAllNodes() []*Node {
	return nil
}

func (store storeImpl) ReadConsensusNodes() []*Node {
	return nil
}

func (store storeImpl) ReadTransaction(hash crypto.Hash) (*VersionedTransaction, string, error) {
	return nil, "", nil
}

func (store storeImpl) CheckDepositInput(deposit *DepositData, tx crypto.Hash) error {
	return nil
}

func (store storeImpl) LockDepositInput(deposit *DepositData, tx crypto.Hash, fork bool) error {
	return nil
}

func (store storeImpl) ReadLastMintDistribution(group string) (*MintDistribution, error) {
	return nil, nil
}

func (store storeImpl) LockMintInput(mint *MintData, tx crypto.Hash, fork bool) error {
	return nil
}

func (store storeImpl) LockWithdrawalClaim(hash, tx crypto.Hash, fork bool) error {
	return nil
}
