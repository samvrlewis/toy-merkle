/*

Building a simple Merkle Tree

Exercise 1:
    Given a set of data D, construct a Merkle Tree.

Assume that D is a power of 2 (the binary tree is perfect).

Example input:
    D = [A1, A2, A3, A4]

Example output:

                               Root
                           ┌──────────┐
                           │    H7    │
                           │ H(H5|H6) │
                  ┌────────┴──────────┴──────────┐
                  │                              │
                  │                              │
             ┌────┴─────┐                  ┌─────┴────┐
             │    H5    │                  │    H6    │
             │ H(H1|H2) │                  │ H(H3|H4) │
             └─┬─────┬──┘                  └─┬──────┬─┘
               │     │                       │      │
     ┌─────────┴┐   ┌┴─────────┐    ┌────────┴─┐  ┌─┴────────┐
     │   H1     │   │    H2    │    │    H3    │  │    H4    │
     │  H(A1)   │   │   H(A2)  │    │   H(A3)  │  │   H(A4)  │
     └───┬──────┘   └────┬─────┘    └────┬─────┘  └────┬─────┘
         │               │               │             │
         A1              A2              A3            A4


Exercise 1b:
    Write a function that will verify a given set of data with a given root hash.

Please share your github answer to us.

*/

#![allow(dead_code)]
#![allow(unused_variables)]
use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

pub struct MerkleTree {
    pub nodes: Vec<Hash>,
    pub levels: usize,
}

/// Which side to put Hash on when concatenating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatenating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

#[derive(Debug)]
pub enum Error {
    CantFindDataInMerkleTree,
    IndexIsNotALeaf,
}

type Result<T> = std::result::Result<T, Error>;

impl MerkleTree {
    fn construct_level_up(level: &[Hash]) -> Vec<Hash> {
        assert!(is_power_of_two(level.len()));

        // Step through the previous level, finding the parents by concatenating the children hashes
        level
            .chunks(2)
            .map(|pair| hash_concat(&pair[0], &pair[1]))
            .collect()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        // Normally I would return a result here instead of asserting, but I'm
        // keeping with the supplied function signature
        assert!(is_power_of_two(input.len()));

        // Get the hashes of our input data. These will be the leaves of the Merkle tree
        let mut hashes: Vec<Vec<Hash>> = vec![input.iter().map(hash_data).collect()];
        let mut last_level = &hashes[0];

        let num_levels = (input.len() as f64).log2() as usize;

        // Iterate up the tree, one level up at a time, computing the nodes at the next level
        for _ in 0..num_levels {
            let mut next_level = vec![MerkleTree::construct_level_up(last_level)];
            hashes.append(&mut next_level);
            last_level = &hashes[hashes.len() - 1];
        }

        MerkleTree {
            nodes: hashes.into_iter().flatten().collect(),
            levels: num_levels + 1,
        }
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        MerkleTree::construct(input).root_hash() == *root_hash
    }

    /// Returns the root hash of the Merkle tree
    pub fn root_hash(&self) -> Hash {
        self.nodes[self.nodes.len() - 1].clone()
    }

    /// Returns how many pieces of data were used to construct the Merkle tree
    pub fn num_leaves(&self) -> usize {
        2_usize.pow((self.levels - 1) as u32)
    }

    /// Returns the leaves (the hashes of the underlying data) of the Merkle tree
    fn leaves(&self) -> &[Hash] {
        &self.nodes[0..self.num_leaves()]
    }

    /// Returns the index of the node that is the parent to the given node index
    fn parent_index(&self, index: usize) -> usize {
        // This function should only be used internally, so asserts here should be fine
        assert!(index != self.nodes.len() - 1, "Root node has no parent");
        assert!(index < self.nodes.len(), "Index outside of tree");

        self.nodes.len() - ((self.nodes.len() - index) / 2)
    }

    /// Produces a Merkle proof for the given leaf index
    /// returns an error if the index doesn't correspond to a leaf
    pub fn get_merkle_proof_by_index(&self, leaf_index: usize) -> Result<Proof> {
        if leaf_index >= self.num_leaves() {
            return Err(Error::IndexIsNotALeaf);
        }

        let mut proof = Proof::default();
        let mut current_known_index = leaf_index;

        for level in 0..self.levels - 1 {
            // We already know (or already can compute) the hash of one side of
            // the pair, so just need to return the other for the proof
            let corresponding_hash = if current_known_index % 2 == 0 {
                (HashDirection::Right, &self.nodes[current_known_index + 1])
            } else {
                (HashDirection::Left, &self.nodes[current_known_index - 1])
            };

            proof.hashes.push(corresponding_hash);

            // Now we are able to calculate hash of the parent, so the parent of
            // this node is now the known node
            current_known_index = self.parent_index(current_known_index);
        }

        Ok(proof)
    }

    /// Produces a Merkle proof for the first occurrence of the given data
    /// returns an error if the data cant be found in the merkle tree
    pub fn get_merkle_proof_by_data(&self, data: &Data) -> Result<Proof> {
        let data_hash = hash_data(data);
        let leaf_index = self
            .leaves()
            .iter()
            .position(|leaf| *leaf == data_hash)
            .ok_or(Error::CantFindDataInMerkleTree)?;

        self.get_merkle_proof_by_index(leaf_index)
    }
}

/// Verifies that the given proof is valid for a given root hash and data
pub fn verify_merkle_proof(proof: &Proof, data: &Data, root_hash: &Hash) -> bool {
    let mut current_hash = hash_data(data);

    for (hash_direction, hash) in proof.hashes.iter() {
        current_hash = match hash_direction {
            HashDirection::Left => hash_concat(hash, &current_hash),
            HashDirection::Right => hash_concat(&current_hash, hash),
        };
    }

    current_hash == *root_hash
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_2_level_tree() {
        let data = vec![Data::from("A"), Data::from("B")];

        assert!(MerkleTree::verify(
            &data,
            &hash_concat(&hash_data(&data[0]), &hash_data(&data[1]))
        ));

        let tree = MerkleTree::construct(&data);

        assert_eq!(tree.levels, 2);
        assert_eq!(tree.num_leaves(), 2);
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.leaves().len(), 2);
    }

    #[test]
    fn test_3_level_tree() {
        let data = vec![
            Data::from("AAA"),
            Data::from("BBB"),
            Data::from("CCC"),
            Data::from("DDD"),
        ];

        let expected_hash = hash_concat(
            &hash_concat(&hash_data(&data[0]), &hash_data(&data[1])),
            &hash_concat(&hash_data(&data[2]), &hash_data(&data[3])),
        );

        assert!(MerkleTree::verify(&data, &expected_hash));

        let tree = MerkleTree::construct(&data);

        assert_eq!(tree.levels, 3);
        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(tree.nodes.len(), 7);
        assert_eq!(tree.leaves().len(), 4);
    }

    #[test]
    fn test_4_level_tree() {
        let data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
            Data::from("EEEE"),
            Data::from("FFFF"),
            Data::from("GGGG"),
            Data::from("HHHH"),
        ];

        let expected_hash = hash_concat(
            &hash_concat(
                &hash_concat(&hash_data(&data[0]), &hash_data(&data[1])),
                &hash_concat(&hash_data(&data[2]), &hash_data(&data[3])),
            ),
            &hash_concat(
                &hash_concat(&hash_data(&data[4]), &hash_data(&data[5])),
                &hash_concat(&hash_data(&data[6]), &hash_data(&data[7])),
            ),
        );

        assert!(MerkleTree::verify(&data, &expected_hash));

        let tree = MerkleTree::construct(&data);

        assert_eq!(tree.levels, 4);
        assert_eq!(tree.num_leaves(), 8);
        assert_eq!(tree.nodes.len(), 15);
        assert_eq!(tree.leaves().len(), 8);
    }

    #[test]
    fn test_verify_merkle_proof() {
        let data = vec![Data::from("AAAA"), Data::from("BBBB")];

        let tree = MerkleTree::construct(&data);
        let proof = tree
            .get_merkle_proof_by_data(&Data::from("AAAA"))
            .expect("Should be able to create proof");

        assert!(verify_merkle_proof(
            &proof,
            &Data::from("AAAA"),
            &tree.root_hash()
        ));

        let proof = tree
            .get_merkle_proof_by_data(&Data::from("BBBB"))
            .expect("Should be able to create proof");

        assert!(verify_merkle_proof(
            &proof,
            &Data::from("BBBB"),
            &tree.root_hash()
        ));
    }

    #[test]
    fn test_verify_merkle_proof_larger() {
        let data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
        ];

        let tree = MerkleTree::construct(&data);

        let proof = tree
            .get_merkle_proof_by_data(&Data::from("AAAA"))
            .expect("Should be able to create proof");
        assert!(verify_merkle_proof(
            &proof,
            &Data::from("AAAA"),
            &tree.root_hash()
        ));
    }

    #[test]
    fn test_verify_merkle_tree_middle_node() {
        let data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
        ];

        let tree = MerkleTree::construct(&data);
        let proof = tree
            .get_merkle_proof_by_data(&Data::from("DDDD"))
            .expect("Should be able to create proof");
        assert!(verify_merkle_proof(
            &proof,
            &Data::from("DDDD"),
            &tree.root_hash()
        ));
    }

    #[test]
    fn test_verify_merkle_tree_8() {
        let data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
            Data::from("EEEE"),
            Data::from("FFFF"),
            Data::from("GGGG"),
            Data::from("HHHH"),
        ];

        let tree = MerkleTree::construct(&data);

        for data_leaf in data {
            let proof = tree
                .get_merkle_proof_by_data(&data_leaf)
                .expect("Should be able to create proof");
            assert!(verify_merkle_proof(&proof, &data_leaf, &tree.root_hash()));
        }
    }

    #[test]
    fn test_verify_merkle_tree_16() {
        let data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
            Data::from("EEEE"),
            Data::from("FFFF"),
            Data::from("GGGG"),
            Data::from("HHHH"),
            Data::from("IIII"),
            Data::from("JJJJ"),
            Data::from("KKKK"),
            Data::from("LLLL"),
            Data::from("MMMM"),
            Data::from("NNNN"),
            Data::from("OOOO"),
            Data::from("PPPP"),
        ];

        let tree = MerkleTree::construct(&data);

        for data_leaf in data {
            let proof = tree
                .get_merkle_proof_by_data(&data_leaf)
                .expect("Should be able to create proof");
            assert!(verify_merkle_proof(&proof, &data_leaf, &tree.root_hash()));
        }
    }

    #[test]
    fn test_merkle_proof_fails_for_wrong_data() {
        let data = vec![Data::from("AAAA"), Data::from("BBBB")];

        let tree = MerkleTree::construct(&data);
        let proof = tree
            .get_merkle_proof_by_data(&Data::from("BBBB"))
            .expect("Should be able to create proof");
        assert!(!verify_merkle_proof(
            &proof,
            &Data::from("AAAA"),
            &tree.root_hash()
        ));
    }

    #[test]
    fn test_merkle_proof_fails_for_wrong_tree() {
        let data = vec![Data::from("AAAA"), Data::from("BBBB")];

        let tree = MerkleTree::construct(&data);

        let other_data = vec![
            Data::from("AAAA"),
            Data::from("BBBB"),
            Data::from("CCCC"),
            Data::from("DDDD"),
        ];

        let other_tree = MerkleTree::construct(&other_data);

        let proof = tree
            .get_merkle_proof_by_data(&Data::from("AAAA"))
            .expect("Should be able to create proof");
        assert!(!verify_merkle_proof(
            &proof,
            &Data::from("AAAA"),
            &other_tree.root_hash()
        ));
    }

    #[test]
    fn test_merkle_proof_fails_if_tree_changed() {
        let data = vec![Data::from("AAAA"), Data::from("BBBB")];

        let tree = MerkleTree::construct(&data);

        let other_data = vec![Data::from("AAAA"), Data::from("BBBA")];

        let other_tree = MerkleTree::construct(&other_data);

        let proof = tree
            .get_merkle_proof_by_data(&Data::from("AAAA"))
            .expect("Should be able to create proof");

        assert!(!verify_merkle_proof(
            &proof,
            &Data::from("AAAA"),
            &other_tree.root_hash()
        ));
    }
}
