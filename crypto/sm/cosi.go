// +build sm,custom_alg

package sm

import (
	"encoding/binary"
	"fmt"

	"github.com/fox-one/mixin/crypto"
)

func (f keyFactory) CosiAggregateCommitments(cosi *crypto.CosiSignature, commitments map[int]*crypto.Commitment) error {
	return nil
}

func (f keyFactory) UpdateSignatureCommitment(sig *crypto.Signature, commitment *crypto.Commitment) {}

func (f keyFactory) DumpSignatureResponse(sig *crypto.Signature) *crypto.Response {
	var response crypto.Response
	copy(response[:], sig[:])
	return &response
}

func (f keyFactory) LoadResponseSignature(cosi *crypto.CosiSignature, commitment *crypto.Commitment, response *crypto.Response) *crypto.Signature {
	var sig crypto.Signature
	copy(sig[:], response[:])
	return &sig
}

func (f keyFactory) CosiDumps(cosi *crypto.CosiSignature) (data []byte) {
	mask := make([]byte, 8)
	binary.BigEndian.PutUint64(mask, cosi.Mask)
	sigMask := make([]byte, 8)
	binary.BigEndian.PutUint64(sigMask, cosi.SignatureMask)
	data = append(mask[:], sigMask...)
	for _, sig := range cosi.Signatures {
		data = append(data, sig[:]...)
	}
	return
}

func (f keyFactory) CosiLoads(cosi *crypto.CosiSignature, data []byte) (rest []byte, err error) {
	if len(data) < 16 {
		err = fmt.Errorf("invalid challenge message size %d", len(data))
		return
	}

	cosi.Mask = binary.BigEndian.Uint64(data[:8])
	cosi.SignatureMask = cosi.Mask
	sigMask := binary.BigEndian.Uint64(data[8:16])
	rest = data[16:]
	for _, i := range cosi.Keys() {
		if sigMask&(1<<i) == 0 {
			if len(rest) < 64 {
				err = fmt.Errorf("invalid challenge message size %d", len(data))
				return
			}
			var sig crypto.Signature
			copy(sig[:], rest[:64])
			if err = cosi.AggregateSignature(i, &sig); err != nil {
				return
			}
			rest = rest[64:]
		}
	}
	return
}

func (f keyFactory) CosiChallenge(cosi *crypto.CosiSignature, publics map[int]crypto.PublicKey, message []byte) ([32]byte, error) {
	return [32]byte{}, nil
}

func (f keyFactory) CosiAggregateSignature(cosi *crypto.CosiSignature, keyIndex int, sig *crypto.Signature) error {
	index := 0
	for i, k := range cosi.Keys() {
		if i >= keyIndex {
			break
		}
		if cosi.SignatureAggregated(k) {
			index++
		}
	}
	sigs := make([]crypto.Signature, len(cosi.Signatures)+1)
	sigs[index] = *sig

	if index > 0 {
		copy(sigs[:index], cosi.Signatures[:index])
	}
	if index < len(cosi.Signatures) {
		copy(sigs[index+1:], cosi.Signatures[index:])
	}
	cosi.Signatures = sigs
	return nil
}

func (f keyFactory) CosiFullVerify(publics map[int]crypto.PublicKey, message []byte, cosi *crypto.CosiSignature) bool {
	if cosi.SignatureMask != 0 {
		return false
	}

	keys := cosi.Keys()
	if len(keys) != len(cosi.Signatures) {
		return false
	}

	for i, k := range keys {
		pub, ok := publics[k]
		if !ok {
			return false
		}
		if !pub.Verify(message, &cosi.Signatures[i]) {
			return false
		}
	}
	return true
}
