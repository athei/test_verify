#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod test_verify {

    use ed25519_compact::*;
    use scale::{Decode, Encode};
    use ink_storage::{collections::{HashMap as StorageHashMap},
    traits::{
        PackedLayout,
        SpreadLayout,
    },
    Lazy};
    use ink_prelude::vec::Vec;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct TestVerify {
        /// Stores a single `bool` value on the storage.
        value: bool,
    }

    #[derive(Encode, Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct EdSignature {
        pub signature_data: Vec<u8>,
        pub signer: Vec<u8>,
    }

    impl TestVerify {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(init_value: bool) -> Self {
            Self { value: init_value }
        }

        /// Constructor that initializes the `bool` value to `false`.
        ///
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new(Default::default())
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn flip(&mut self) {
            self.value = !self.value;
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> bool {
            self.value
        }

        #[ink(message)]
        pub fn get_signer(&self, ed_sig: EdSignature) -> bool {
            let signature: Signature = Signature::from_slice(ed_sig.signature_data.as_slice()).unwrap();
            let message_hash: [u8;32] = [0;32];
            let pub_k: PublicKey = PublicKey::from_slice(ed_sig.signer.as_slice()).unwrap();
            
            let result: bool = pub_k.verify(message_hash.as_ref(), &signature).is_ok();
            result
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[test]
        fn default_works() {
            let test_verify = TestVerify::default();
            assert_eq!(test_verify.get(), false);
        }

        /// We test a simple use case of our contract.
        #[test]
        fn it_works() {
            let mut test_verify = TestVerify::new(false);
            assert_eq!(test_verify.get(), false);
            test_verify.flip();
            assert_eq!(test_verify.get(), true);
        }
    }
}
