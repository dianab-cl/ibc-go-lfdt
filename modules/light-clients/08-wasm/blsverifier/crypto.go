// SPDX-License-Identifier: Apache-2.0

package blsverifier

import (
	"bytes"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

const (
	// PublicKeySize is the size of a compressed BLS12-381 G1 public key.
	PublicKeySize = blst.BLST_P1_COMPRESS_BYTES
	// SignatureSize is the size of a compressed BLS12-381 G2 signature.
	SignatureSize = blst.BLST_P2_COMPRESS_BYTES
)

// dst is the Ethereum consensus proof-of-possession ciphersuite domain separation tag.
var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// PublicKey is a compressed BLS12-381 G1 public key.
type PublicKey []byte

// Marshal returns a copy of the compressed public key bytes.
func (pk PublicKey) Marshal() []byte {
	return bytes.Clone(pk)
}

// AggregatePublicKeys validates the compressed public keys and returns their aggregate.
func AggregatePublicKeys(publicKeys [][]byte) (PublicKey, error) {
	pk, err := aggregatePublicKeys(publicKeys)
	if err != nil {
		return nil, err
	}
	return PublicKey(pk.Compress()), nil
}

// VerifySignature verifies a compressed signature over message against the aggregate of publicKeys.
func VerifySignature(signature []byte, message [32]byte, publicKeys [][]byte) (bool, error) {
	pk, err := aggregatePublicKeys(publicKeys)
	if err != nil {
		return false, fmt.Errorf("failed to aggregate public keys %w", err)
	}

	if len(signature) != SignatureSize {
		return false, fmt.Errorf("signature must be %d bytes", SignatureSize)
	}
	sig := new(blst.P2Affine).Uncompress(signature)
	if sig == nil {
		return false, errors.New("could not unmarshal bytes into signature")
	}
	// Subgroup check only: an aggregate signature may be the point at infinity.
	if !sig.SigValidate(false) {
		return false, errors.New("signature not in group")
	}

	// Signature and key are already validated above.
	return sig.Verify(false, pk, false, message[:], dst), nil
}

func aggregatePublicKeys(publicKeys [][]byte) (*blst.P1Affine, error) {
	if len(publicKeys) == 0 {
		return nil, errors.New("nil or empty public keys")
	}

	agg := new(blst.P1Aggregate)
	for _, bz := range publicKeys {
		if len(bz) != PublicKeySize {
			return nil, fmt.Errorf("public key must be %d bytes", PublicKeySize)
		}
		pk := new(blst.P1Affine).Uncompress(bz)
		if pk == nil {
			return nil, errors.New("could not unmarshal bytes into public key")
		}
		// Rejects the point at infinity and points outside the subgroup.
		if !pk.KeyValidate() {
			return nil, errors.New("received an infinite public key")
		}
		agg.Add(pk, false)
	}

	return agg.ToAffine(), nil
}
