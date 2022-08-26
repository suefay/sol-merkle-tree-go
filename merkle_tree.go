package solmerkle

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// MerkleTree implements a general purpose Merkle tree.
type MerkleTree struct {
	branches     [][][]byte
	depth        uint64
	duplicateOdd bool
}

func GenerateTreeFromItems(items [][]byte, duplicateOdd bool) (*MerkleTree, error) {
	// Pad all items to 32 bytes.
	leaves := copy2dBytes(items)
	for i := range leaves {
		leaves[i] = hash(padTo(leaves[i], 32))
	}
	return GenerateTreeFromHashedItems(leaves, duplicateOdd)
}

// GenerateTreeFromItems constructs a Merkle tree from a sequence of byte slices.
func GenerateTreeFromHashedItems(items [][]byte, duplicateOdd bool) (*MerkleTree, error) {
	if len(items) == 0 {
		return nil, errors.New("no items provided to generate Merkle tree")
	}
	// Clone the slice to prevent mutation.
	leaves := copy2dBytes(items)

	// Sort by byte contents.
	sort.Slice(leaves, func(i, j int) bool {
		return lessThanBytes(leaves[i], leaves[j])
	})

	if duplicateOdd {
		// Even out if uneven.
		if len(leaves)%2 == 1 {
			duplicate := safeCopyBytes(leaves[len(leaves)-1])
			leaves = append(leaves, duplicate)
		}
		// Append duplicate nodes until even.
		nextPowOfItems := nextPowerOf2(uint64(len(leaves)))
		for len(leaves) < int(nextPowOfItems) {
			leaves = append(leaves, leaves[len(leaves)-2], leaves[len(leaves)-1])
		}
	}

	var depth uint64
	maxDepth := uint64(math.Log2(float64(len(leaves)))) + 1

	layers := make([][][]byte, maxDepth+1)
	layers[0] = leaves

	for i := uint64(0); len(layers[i]) > 1; i++ {
		var updatedValues [][]byte
		for j := 0; j < len(layers[i]); j += 2 {
			var concat []byte

			if j+1 == len(layers[i]) && len(layers[i])%2 == 1 {
				concat = layers[i][j]
			} else {
				concat = SortAndHash(layers[i][j], layers[i][j+1])
			}

			updatedValues = append(updatedValues, concat[:])
		}

		layers[i+1] = updatedValues
		depth++
	}

	return &MerkleTree{
		branches:     layers[0 : depth+1],
		depth:        depth,
		duplicateOdd: duplicateOdd,
	}, nil
}

// Items returns the original items passed in when creating the Merkle tree.
func (m *MerkleTree) Items() [][]byte {
	return m.branches[0]
}

// Root returns the top-most, Merkle root of the tree.
func (m *MerkleTree) Root() []byte {
	return m.branches[len(m.branches)-1][0]
}

// Layers returns all layers of the tree.
func (m *MerkleTree) Layers() [][][]byte {
	return m.branches
}

// MerkleProof computes a Proof for a leaf from a tree's branches.
func (m *MerkleTree) MerkleProof(leaf []byte) ([][]byte, error) {
	nextLeaf := leaf
	proof := make([][]byte, 0)
	for i := uint64(0); i < m.depth; i++ {
		leftLeaf, rightLeaf, isLastOdd, err := leafPair(m.branches[i], nextLeaf)
		if err != nil {
			return nil, fmt.Errorf("could not find pair: %v", err)
		}
		if !isLastOdd {
			if bytes.Equal(leftLeaf, nextLeaf) {
				proof = append(proof, rightLeaf)
			} else {
				proof = append(proof, leftLeaf)
			}

			nextLeaf = hash(leftLeaf, rightLeaf)
		}
	}

	return proof, nil
}

func (m *MerkleTree) MerkleProofOfIndex(indexOfLeaf uint64) ([][]byte, error) {
	if int(indexOfLeaf) > len(m.branches[0]) {
		return nil, fmt.Errorf("could not find index %d, greater than length %d", indexOfLeaf, m.branches[0])
	}
	return m.MerkleProof(m.branches[0][indexOfLeaf])
}

// VerifyMerkleBranch verifies a Merkle branch against a root of a tree.
func VerifyMerkleBranch(root, item []byte, proof [][]byte) bool {
	node := safeCopyBytes(item)
	for i := 0; i < len(proof); i++ {
		if lessThanBytes(node, proof[i]) {
			node = hash(node[:], proof[i])
		} else {
			node = hash(proof[i], node[:])
		}
	}

	return bytes.Equal(root, node[:])
}

func leafPair(leaves [][]byte, leaf []byte) ([]byte, []byte, bool, error) {
	var found bool
	var indexOfLeaf int
	for i, item := range leaves {
		if bytes.Equal(item, leaf) {
			indexOfLeaf = i
			found = true
			break
		}
	}
	if !found {
		return nil, nil, false, fmt.Errorf("could not find leaf %#x", leaf)
	}

	var otherLeaf []byte
	var leftLeaf []byte
	var rightLeaf []byte
	var isLastOdd bool

	if indexOfLeaf == len(leaves)-1 && len(leaves)%2 == 1 {
		isLastOdd = true
	} else {
		// Chcek if the leaf is on the left side.
		if indexOfLeaf%2 == 0 {
			otherLeaf = safeCopyBytes(leaves[indexOfLeaf+1])
		} else {
			otherLeaf = safeCopyBytes(leaves[indexOfLeaf-1])
		}

		leftLeaf, rightLeaf = Sort2Bytes(leaf, otherLeaf)
	}

	return leftLeaf, rightLeaf, isLastOdd, nil
}

// SortAndHash sorts the 2 bytes and keccak256 hashes them.
func SortAndHash(i []byte, j []byte) []byte {
	sorted1, sorted2 := Sort2Bytes(i, j)
	return hash(sorted1, sorted2)
}

func hash(data ...[]byte) []byte {
	return crypto.Keccak256(data...)
}
