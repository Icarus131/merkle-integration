extern crate sha2;
use ff::{PrimeField, PrimeFieldBits};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Element<F: PrimeField + PrimeFieldBits> {
    pub value: Vec<F>,
}

impl<F: PrimeField + PrimeFieldBits> Default for Element<F> {
    fn default() -> Self {
        Self {
            value: vec![F::ZERO],
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> Element<F> {
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for v in &self.value {
            hasher.update(v.to_repr().as_ref());
        }
        hasher.finalize().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct BinaryTree<F: PrimeField + PrimeFieldBits> {
    pub top: Vec<u8>,
    pub data_store: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField + PrimeFieldBits> BinaryTree<F> {
    pub fn initialize(empty_value: Element<F>, height: usize) -> Self {
        let mut data_store = HashMap::<Vec<u8>, (Vec<u8>, Vec<u8>)>::new();
        let mut current_hash = empty_value.compute_hash();
        for _ in 0..height {
            let pair = (current_hash.clone(), current_hash.clone());
            current_hash = Self::combine_hashes(&current_hash, &current_hash);
            data_store.insert(current_hash.clone(), pair);
        }
        Self {
            top: current_hash,
            data_store,
            _marker: PhantomData,
        }
    }

    pub fn add_element(&mut self, mut bits_index: Vec<bool>, element: &Element<F>) {
        let mut path = self.get_sibling_hashes(&bits_index);
        bits_index.reverse();
        let mut current_hash = element.compute_hash();
        for direction in bits_index {
            let sibling = path.pop().unwrap();
            let (left, right) = if direction {
                (sibling, current_hash.clone())
            } else {
                (current_hash.clone(), sibling)
            };
            current_hash = Self::combine_hashes(&left, &right);
            self.data_store.insert(current_hash.clone(), (left, right));
        }
        self.top = current_hash;
    }

    fn combine_hashes(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
    }

    pub fn get_sibling_hashes(&self, bits_index: &[bool]) -> Vec<Vec<u8>> {
        let mut node_hash = self.top.clone();
        let mut siblings = Vec::<Vec<u8>>::new();
        for &direction in bits_index {
            let (left, right) = self.data_store.get(&node_hash).unwrap();
            if direction {
                node_hash = right.clone();
                siblings.push(left.clone());
            } else {
                node_hash = left.clone();
                siblings.push(right.clone());
            }
        }
        siblings
    }
}

pub fn convert_to_bits(depth: usize, index: u64) -> Vec<bool> {
    let mut bits: Vec<bool> = (0..depth).map(|i| ((index >> i) & 1) == 1).collect();
    bits.reverse();
    bits
}

pub struct Proof {
    pub sibling_hashes: Vec<Vec<u8>>,
}

impl Proof {
    pub fn calculate_root<F: PrimeField + PrimeFieldBits>(
        &self,
        mut bits_index: Vec<bool>,
        element: &Element<F>,
    ) -> Vec<u8> {
        bits_index.reverse();
        let mut current_hash = element.compute_hash();
        for (i, sibling) in self.sibling_hashes.iter().rev().enumerate() {
            let (left, right) = if bits_index[i] {
                (sibling, &current_hash)
            } else {
                (&current_hash, sibling)
            };
            current_hash = BinaryTree::<F>::combine_hashes(left, right);
        }
        current_hash
    }

    pub fn validate<F: PrimeField + PrimeFieldBits>(
        &self,
        bits_index: Vec<bool>,
        element: &Element<F>,
        root_hash: &[u8],
    ) -> bool {
        self.calculate_root(bits_index, element) == root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::Fp;

    #[test]
    fn binary_tree_test() {
        const HEIGHT: usize = 32;
        let empty_element = Element::<Fp>::default();
        let mut tree = BinaryTree::<Fp>::initialize(empty_element.clone(), HEIGHT);

        for i in 0..50 {
            let index = i;
            let bits_index = convert_to_bits(HEIGHT, index);
            let element = Element {
                value: vec![Fp::random(&mut rand::thread_rng())],
            };

            let path_siblings = tree.get_sibling_hashes(&bits_index);
            let proof = Proof {
                sibling_hashes: path_siblings,
            };
            assert!(!proof.validate(bits_index.clone(), &element, &tree.top));
            tree.add_element(bits_index.clone(), &element);
            let new_path_siblings = tree.get_sibling_hashes(&bits_index);
            let new_proof = Proof {
                sibling_hashes: new_path_siblings,
            };
            assert!(new_proof.validate(bits_index, &element, &tree.top));
        }
    }
}
