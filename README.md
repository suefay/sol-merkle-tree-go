# Sol-merkle-tree-go

This is a simple merkle tree implementation in go for use within solidity. This was specifically written for use with Uniswaps [merkle-distributor](https://github.com/Uniswap/merkle-distributor).

## Usage
```golang
import (
	"fmt"
	"math/big"

	solmerkle "github.com/suefay/sol-merkle-tree-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type User struct {
	index uint64
	account common.Address
	amount *big.Int
}

type ClaimInfo struct {
	Index  uint64
	Amount string
	Proof  []string
}

func createDistributionTree(holderArray []*tokenHolder) (map[string]ClaimInfo, error) {
    // Put per-user proof data into an array of structs. 
	elements := make([]*User, len(holderArray))
	for i, holder := range holderArray {
		elements[i] = &User{
			index: uint64(i),
			account: holder.addr,
			amount: holder.balance,
		}
	}

    // Solidity hash the data to use as tree leaves. 
nodes := make([][]byte, len(elements))
	for i, user := range elements {
		packed := append(
			uint64To256BytesLittleEndian(user.index),
			append(
				user.account.Bytes(),
				common.LeftPadBytes(user.amount.Bytes(), 32)...,
			)...,
		)
		nodes[i] = crypto.Keccak256(packed)
	}

    // Create the tree. 
	tree, err := solmerkle.GenerateTreeFromHashedItems(nodes, false)
	if err != nil {
		return nil, fmt.Errorf("could not generate trie: %v", err)
	}
	distributionRoot := tree.Root()

    // Place info for claiming into a map. 
	addrToProof := make(map[string]ClaimInfo, len(holderArray))
	for i, holder := range holderArray {
		proof, err := tree.MerkleProof(nodes[i])
		if err != nil {
			return nil, fmt.Errorf("could not generate proof: %v", err)
		}
		addrToProof[holder.addr.String()] = ClaimInfo{
			Index:  uint64(i),
			Amount: holder.balance.String(),
			Proof:  stringArrayFrom2DBytes(proof),
		}
	}
	addrToProof["root"] = ClaimInfo{Amount: fmt.Sprintf("%#x", distributionRoot)}
	return addrToProof, nil
}
```
