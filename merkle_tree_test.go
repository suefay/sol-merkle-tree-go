package solmerkle

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestGenerateTrieFromItems(t *testing.T) {
	tests := []struct {
		name     string
		items    [][]byte
		wantRoot []byte
		wantErr  bool
	}{
		{
			name: "simple sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{4}, 32),
			},
			wantRoot: common.Hex2Bytes("2e062ab1c855bfc38612bab4c636b67b9f466a193f23f6867cc19d259c0dc334"),
		},
		{
			name: "larger not sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
			},
			wantRoot: common.Hex2Bytes("f0d2633b9a01765034e5ab2bb86950d4f961ea2f31038795e27954cd26f978ce"),
		},
		{
			name: "larger and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
			},
			wantRoot: common.Hex2Bytes("af6c5f75b9a0d2264bd267446c83b59e0d10df482f1f8d58339f6b1a7a681ae6"),
		},
		{
			name: "very large and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{10}, 32),
				padTo([]byte{20}, 32),
				padTo([]byte{100}, 32),
				padTo([]byte{112}, 32),
				padTo([]byte{80}, 32),
				padTo([]byte{32}, 32),
				padTo([]byte{55}, 32),
				padTo([]byte{56}, 32),
				padTo([]byte{120}, 32),
				padTo([]byte{59}, 32),
				padTo([]byte{70}, 32),
				padTo([]byte{60}, 32),
			},
			wantRoot: common.Hex2Bytes("c0ac0b29e2449bbf0939a318fe2898d1158774adacc293198ae706d4bf128adf"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateTreeFromItems(tt.items, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTreeFromItems() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Fatal("got == nil")
			}

			for i := 0; i < len(got.branches); i++ {
				for j := 0; j < len(got.branches[i]); j++ {
					t.Logf("%#x", got.branches[i][j])
				}
			}

			root := got.Root()
			if !bytes.Equal(root, tt.wantRoot) {
				t.Errorf("root() got = %#x, want %#x", root, tt.wantRoot)
			}
		})
	}
}

func TestMerkleProof(t *testing.T) {
	tests := []struct {
		name        string
		items       [][]byte
		itemToProve []byte
		wantProof   [][]byte
		wantErr     bool
	}{
		{
			name: "larger not sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
			},
			itemToProve: common.Hex2Bytes("5723d2c3a83af9b735e3b7f21531e5623d183a9095a56604ead41f3582fdfb75"),
			wantProof: [][]byte{
				common.Hex2Bytes("cc969683f9149b325f7a900071a421ed89ed4dbc0c9dab44480d32b66ed29088"),
				common.Hex2Bytes("652bdb6779269ffd9606323a76cfc930027ec1f9af31f581f02973476412ccbd"),
				common.Hex2Bytes("6b627580b5cb9c5f0e6491994f2dc4859ac6eba43449055c53861c6fd05148cd"),
			},
		},
		{
			name: "larger and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
			},
			itemToProve: common.Hex2Bytes("cc969683f9149b325f7a900071a421ed89ed4dbc0c9dab44480d32b66ed29088"),
			wantProof: [][]byte{
				common.Hex2Bytes("cc969683f9149b325f7a900071a421ed89ed4dbc0c9dab44480d32b66ed29088"),
				common.Hex2Bytes("339ce64dfea64e35185aa30ebe0bd14ea07c03877ad17ecc51fc8ca8b098e7b2"),
				common.Hex2Bytes("c87adecd2ddb1e3378f0a6b069f7fb78afc05272f6f00decb90edfb3fbc51e2c"),
				common.Hex2Bytes("1772386e105fd8dd137d69e14d9c6620aebcae51f50eabd046d0222749755fa0"),
			},
		},
		{
			name: "very large and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{10}, 32),
				padTo([]byte{20}, 32),
				padTo([]byte{100}, 32),
				padTo([]byte{112}, 32),
				padTo([]byte{80}, 32),
				padTo([]byte{32}, 32),
				padTo([]byte{55}, 32),
				padTo([]byte{56}, 32),
				padTo([]byte{120}, 32),
				padTo([]byte{59}, 32),
				padTo([]byte{70}, 32),
				padTo([]byte{60}, 32),
			},
			itemToProve: common.Hex2Bytes("382e3c198d933f7462412341b2cc6d0b12215af5adc803ad40dfe5f44a444e0f"),
			wantProof: [][]byte{
				common.Hex2Bytes("382e3c198d933f7462412341b2cc6d0b12215af5adc803ad40dfe5f44a444e0f"),
				common.Hex2Bytes("e23fa5d990f321d8be1a5aaa34ec48f8248f0f416f4fd05cead2cf0a15007eaf"),
				common.Hex2Bytes("16068cdc834c589e6dfc5757417bd41ee47ede31e5e58f548ddbf936d0789578"),
				common.Hex2Bytes("dd5c06296f49e41babc319f48a17778b5f33ef5e9b6750e4cc53ccd0e7b18723"),
				common.Hex2Bytes("1d87197e80d62f8af995d1a8df69efa3996dac57e16757452997f615c0bdcc68"),
			},
		},
		{
			name: "very large and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{10}, 32),
				padTo([]byte{20}, 32),
				padTo([]byte{100}, 32),
				padTo([]byte{112}, 32),
				padTo([]byte{80}, 32),
				padTo([]byte{32}, 32),
				padTo([]byte{55}, 32),
				padTo([]byte{56}, 32),
				padTo([]byte{120}, 32),
				padTo([]byte{59}, 32),
				padTo([]byte{70}, 32),
				padTo([]byte{60}, 32),
			},
			itemToProve: common.Hex2Bytes("beef3c198d933f7462412341b2cc6d0b12215af5adc803ad40dfe5f44a444e0f"),
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateTreeFromItems(tt.items, true)
			if err != nil {
				t.Error(err)
				return
			}
			proof, err := got.MerkleProof(tt.itemToProve)
			if (err != nil) != tt.wantErr {
				t.Errorf("MerkleProof() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, pp := range proof {
				if !bytes.Equal(tt.wantProof[i], pp) {
					t.Errorf("proof() got = %#x, want %#x", tt.wantProof[i], pp)
				}
			}
		})
	}
}

func TestVerifyMerkleBranch(t *testing.T) {
	tests := []struct {
		name    string
		root    []byte
		item    []byte
		proof   [][]byte
		success bool
	}{
		{
			name: "simple",
			root: common.Hex2Bytes("2e062ab1c855bfc38612bab4c636b67b9f466a193f23f6867cc19d259c0dc334"),
			item: common.Hex2Bytes("426fcb404ab2d5d8e61a3d918108006bbb0a9be65e92235bb10eefbdb6dcd053"),
			proof: [][]byte{
				common.Hex2Bytes("340dd630ad21bf010b4e676dbfa9ba9a02175262d1fa356232cfde6cb5b47ef2"),
				common.Hex2Bytes("b103de8b3738dd100e9b4f9f5f4ce4ae7336d31f2c08892a4b5950926ef0829f"),
			},
			success: true,
		},
		{
			name: "larger",
			root: common.Hex2Bytes("f0d2633b9a01765034e5ab2bb86950d4f961ea2f31038795e27954cd26f978ce"),
			item: common.Hex2Bytes("0c2d1b9c97b15f8a18e224fe94a8453f996465e14217e0939995ce76fbe01129"),
			proof: [][]byte{
				common.Hex2Bytes("0bab70cb415fad57bb66ddb2bfe7e36342284737c8f13d1e6d19f65a726e6fb6"),
				common.Hex2Bytes("abd2e5177fc65d948cb578e48cc6e3518a5252f5ea7dbd0a72e7d6b7c5e46442"),
				common.Hex2Bytes("79cbd20f1282354329b4882ce93016ea6fe3a61531551d8e959912ee400ecdef"),
			},
			success: true,
		},
		{
			name: "larger and uneven",
			root: common.Hex2Bytes("af6c5f75b9a0d2264bd267446c83b59e0d10df482f1f8d58339f6b1a7a681ae6"),
			item: common.Hex2Bytes("cc969683f9149b325f7a900071a421ed89ed4dbc0c9dab44480d32b66ed29088"),
			proof: [][]byte{
				common.Hex2Bytes("cc969683f9149b325f7a900071a421ed89ed4dbc0c9dab44480d32b66ed29088"),
				common.Hex2Bytes("339ce64dfea64e35185aa30ebe0bd14ea07c03877ad17ecc51fc8ca8b098e7b2"),
				common.Hex2Bytes("c87adecd2ddb1e3378f0a6b069f7fb78afc05272f6f00decb90edfb3fbc51e2c"),
				common.Hex2Bytes("1772386e105fd8dd137d69e14d9c6620aebcae51f50eabd046d0222749755fa0"),
			},
			success: true,
		},
		{
			name: "very large and uneven",
			root: common.Hex2Bytes("c0ac0b29e2449bbf0939a318fe2898d1158774adacc293198ae706d4bf128adf"),
			item: common.Hex2Bytes("382e3c198d933f7462412341b2cc6d0b12215af5adc803ad40dfe5f44a444e0f"),
			proof: [][]byte{
				common.Hex2Bytes("382e3c198d933f7462412341b2cc6d0b12215af5adc803ad40dfe5f44a444e0f"),
				common.Hex2Bytes("e23fa5d990f321d8be1a5aaa34ec48f8248f0f416f4fd05cead2cf0a15007eaf"),
				common.Hex2Bytes("16068cdc834c589e6dfc5757417bd41ee47ede31e5e58f548ddbf936d0789578"),
				common.Hex2Bytes("dd5c06296f49e41babc319f48a17778b5f33ef5e9b6750e4cc53ccd0e7b18723"),
				common.Hex2Bytes("1d87197e80d62f8af995d1a8df69efa3996dac57e16757452997f615c0bdcc68"),
			},
			success: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyMerkleBranch(tt.root, tt.item, tt.proof)
			if got != tt.success {
				t.Error("GenerateTreeFromItems() failed")
				return
			}
		})
	}
}
