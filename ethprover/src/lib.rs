use rlp::{Rlp};
use borsh::{BorshDeserialize, BorshSerialize};
use eth_types::*;
//use near_bindgen::near_bindgen;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

//#[near_bindgen]
#[derive(Default, Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct EthProver {
    bridge_smart_contract: String,
}

//#[near_bindgen]
impl EthProver {
    pub fn init(bridge_smart_contract: String) -> Self {
        Self {
            bridge_smart_contract
        }
    }

    fn extract_nibbles(a: Vec<u8>) -> Vec<u8> {
        a.iter().flat_map(|b| vec![b >> 4, b & 0x0F]).collect()
    }

    pub fn verify_log_entry(
        &self,
        log_index: usize,
        log_entry_data: Vec<u8>,
        receipt_data: Vec<u8>,
        header_data: Vec<u8>,
        proof: Vec<Vec<u8>>,
    ) -> bool {
        let log_entry: LogEntry = rlp::decode(log_entry_data.as_slice()).unwrap();
        let receipt: Receipt = rlp::decode(receipt_data.as_slice()).unwrap();
        let header: BlockHeader = rlp::decode(header_data.as_slice()).unwrap();

        // Verify block header was in the bridge
        // TODO: inter-contract call:
        //self.bridge_smart_contract.block_hashes(header.number) == header.hash;

        // Verify log_entry included in receipt
        assert_eq!(receipt.logs[log_index], log_entry);

        // Verify receipt included into header
        Self::verify_trie_proof(
            header.receipts_root,
            rlp::encode(&log_index),
            proof,
            0,
            0,
            receipt_data
        )
    }

    /// Iterate the proof following the key.
    /// Return True if the value at the leaf is equal to the expected value.
    /// @param expected_root is the expected root of the current proof node.
    /// @param key is the key for which we are proving the value.
    /// @param proof is the proof the key nibbles as path.
    /// @param key_index keeps track of the index while stepping through
    ///     the key nibbles.
    /// @param proof_index keeps track of the index while stepping through
    ///     the proof nodes.
    /// @param expected_value is the key's value expected to be stored in
    ///     the last node (leaf node) of the proof.
    ///
    /// Patricia Tree: https://github.com/ethereum/wiki/wiki/patricia-tree
    /// Article:       https://medium.com/@ouvrard.pierre.alain/merkle-proof-verification-for-ethereum-patricia-tree-48f29658eec
    /// Python impl:   https://gist.github.com/paouvrard/7bb947bf5de0fa0dc69d0d254d82252a
    ///
    fn verify_trie_proof(
        expected_root: H256,
        key: Vec<u8>,
        proof: Vec<Vec<u8>>,
        key_index: usize,
        proof_index: usize,
        expected_value: Vec<u8>
    ) -> bool {
        let node = &proof[proof_index];
        let dec = Rlp::new(&node.as_slice());

        if key_index == 0 { // trie root is always a hash
            assert_eq!(near_keccak256(node), (expected_root.0).0);
        }
        else if node.len() < 32 { // if rlp < 32 bytes, then it is not hashed
            assert_eq!(dec.as_raw(), (expected_root.0).0);
        }
        else {
            assert_eq!(near_keccak256(node), (expected_root.0).0);
        }

        if dec.size() == 17 {
            // branch node
            if key_index >= key.len() {
                if dec.at(dec.size() - 1).unwrap().as_raw().to_vec() == expected_value {
                    // value stored in the branch
                    return true;
                }
            }
            else {
                let new_expected_root = dec.at(key[key_index] as usize).unwrap().as_raw();
                if new_expected_root.len() != 0 {
                    return Self::verify_trie_proof(
                        new_expected_root.into(),
                        key,
                        proof,
                        key_index + 1,
                        proof_index + 1,
                        expected_value
                    );
                }
            }
        }
        else if dec.size() == 2 {
            // leaf or extension node
            // get prefix and optional nibble from the first byte
            let nibbles = Self::extract_nibbles(dec.at(0).unwrap().as_raw().to_vec());
            let (prefix, nibble) = (nibbles[0], nibbles[1]);

            if prefix == 2 {
                // even leaf node
                let key_end = &nibbles[2..];
                if key_end == &key[key_index..] && expected_value == dec.at(1).unwrap().as_raw() {
                    return true;
                }
            }
            else if prefix == 3 {
                // odd leaf node
                let key_end = &nibbles[2..];
                if nibble == key[key_index] && key_end == &key[key_index + 1..] && expected_value == dec.at(1).unwrap().as_raw() {
                    return true;
                }
            }
            else if prefix == 0 {
                // even extension node
                let shared_nibbles = &nibbles[2..];
                let extension_length = shared_nibbles.len();
                if shared_nibbles == &key[key_index..key_index + extension_length] {
                    let new_expected_root = dec.at(1).unwrap().as_raw();
                    return Self::verify_trie_proof(
                        new_expected_root.into(),
                        key,
                        proof,
                        key_index + extension_length,
                        proof_index + 1,
                        expected_value
                    );
                }
            }
            else if prefix == 1 {
                // odd extension node
                let shared_nibbles = &nibbles[2..];
                let extension_length = 1 + shared_nibbles.len();
                if nibble == key[key_index] && shared_nibbles == &key[key_index + 1..key_index + extension_length] {
                    let new_expected_root = dec.at(1).unwrap().as_raw();
                    return Self::verify_trie_proof(
                        new_expected_root.into(),
                        key,
                        proof,
                        key_index + extension_length,
                        proof_index + 1,
                        expected_value
                    );
                }
            }
            else {
                panic!("This should not be reached if the proof has the correct format");
            }
        }

        expected_value.len() == 0
    }
}