# Toy Merkle
A toy Merkle tree implementation in Rust which uses SHA2 hashes.

The implementation is constrained to only work with perfect binary trees (trees
that have power of 2 amount of associated data leafs) however users can "pad"
the amount of leaves to work with the library if they do not have a perfect
power of 2 amount of data.

## Root hash
The library can be used to find the root hash of a Merkle tree, given some data.
This might be useful to confirm that a presented root hash contains claimed
data.

```rust
let received_root_hash = 
    0x25, 0xB5, 0x45, 0x7A, 0xA, 0x9C, 0xE5, 0xDA, 0x71, 0xD3, 0x61, 0x3B, 0xFE, 0xE3,
    0x19, 0x72, 0x38, 0xC1, 0xD, 0xD, 0x49, 0x2F, 0x34, 0x44, 0x21, 0x73, 0x67, 0x18, 0xD3,
    0x7D, 0x73, 0xDC,
];

let data = vec![Data::from("Some data"), 
                Data::from("Some more data"),
                Data::from("Some other data"),
                Data::from("Some final data")];

let tree = MerkleTree::construct(&data);
assert!(MerkleTree::verify(tree.root_hash(), &received_root_hash.into())) 
```

## Proof generation
More usefully, the library can also be used to generate Merkle proofs for data
that exists within the tree. This is useful because the proof verifier doesn't
need to construct the entire tree or know about all of the underlying data, in
order to confirm that a piece of data exists within a given tree. Instead, they
only need to know:

- The data that they are checking is in the tree
- The root hash of the tree
- The proof (which consists of `log2(tree_nodes)` hashes) within the tree

```rust
let data = vec![Data::from("Some data"), 
                Data::from("Some more data"),
                Data::from("Some other data"),
                Data::from("Some final data")];

let tree = MerkleTree::construct(&data);
let proof = tree.get_merkle_proof_by_data(&Data::from("Some more data")).expect("Should be able to create proof");

// Use the proof to confirm that the data does exist within the tree.
assert!(verify_merkle_proof(&proof, &Data::from("Some more data"), tree.root_hash()))
```