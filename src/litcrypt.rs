//! LITCRYPT2 
//! ===========
//! 
//! It's a short name of "Literal Encryption", a Rust proc macro that encrypts text using a basic XOR method. It protect plain text from static analysis tools and helps keep your important app safe from cracking activity.
//! 
//! LITCRYPT2 encrypts strings when compiling, keeping them encrypted in both disk and memory while running, and only decrypting them when needed.
//! 
//! This crate is just a maintained and updated fork of the original crate, **LITCRYPT** by **Robin Syihab (r@ansvia.com)**.
//! 
//! USAGE
//! -----
//! 
//! Dependencies:
//! 
//! ```rust
//! [dependencies]
//! litcrypt2 = "0.1.2"
//! ```
//! 
//! Example:
//! 
//! ```rust
//! #[macro_use]
//! extern crate litcrypt2;
//! 
//! use_litcrypt!();
//! 
//! fn main()
//! {
//!     println!("his name is: {}", lc!("Voldemort"));
//! }
//! 
//! fn raw_string()
//! {
//!     println!("The command line console can be found in the path {}", lc!(r"C:\Windows\System32\cmd.exe"));
//! }
//! ```
//! 
//! `use_litcrypt!` macro call should be called first for initialization before you can
//! use `lc!` macro function. 
//! 
//! Please take note that you can set your encryption key to a specific value using the environment variable 
//! `LITCRYPT_ENCRYPT_KEY` before compile. In case that you don't set this environment variable, the crate
//! will generate a random encryption key at compilation time:
//! e.g:
//! 
//!     $ export LITCRYPT_ENCRYPT_KEY="myverysuperdupermegaultrasecretkey"
//! 
//! Litcrypt will encrypt each string written inside `lc!` statically.
//! 
//! Check the output binary using `strings` command to verify:
//! 
//!     $ strings target/debug/my_valuable_app | grep Voldemort
//! 
//! If the output is blank then your valuable string in your app is safe from static analyzer tool
//! like Hexeditor etc.
//! 
//! For working example code see `./examples` directory, and test using:
//! 
//!     $ cargo run --example simple

extern crate proc_macro;
extern crate proc_macro2;
extern crate rand;
extern crate quote;

#[cfg(test)]
#[macro_use(expect)]
extern crate expectest;

use proc_macro::{TokenStream, TokenTree};
use proc_macro2::Literal;
use rand::{rngs::OsRng, RngCore};
use quote::quote;
use std::env;

mod xor;

lazy_static::lazy_static! {
    static ref RAND_SPELL: [u8; 64] = {
        let mut key = [0u8; 64];
        OsRng.fill_bytes(&mut key);
        key
    };
}

#[inline(always)]
fn get_magic_spell() -> Vec<u8> {
    match env::var("LITCRYPT_ENCRYPT_KEY") {
        Ok(key) => {key.as_bytes().to_vec()},
        Err(_) => {
            // `lc!` will call this function multi times
            // we must provide exact same result for each invocation
            // so use static lazy field for cache
            RAND_SPELL.to_vec()
        }
    }
}

/// Sets the encryption key used for encrypting subsequence strings wrapped in a [`lc!`] macro.
///
/// This key is also encrypted an  will not visible in a static analyzer.
#[proc_macro]
pub fn use_litcrypt(_tokens: TokenStream) -> TokenStream {
    let magic_spell = get_magic_spell();

    let encdec_func = quote! {
        pub mod litcrypt_internal {
            // This XOR code taken from https://github.com/zummenix/xor-rs
            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `key` will be an infinitely repeating byte sequence.
            pub fn xor(source: &[u8], key: &[u8]) -> Vec<u8> {
                match key.len() {
                    0 => source.into(),
                    1 => xor_with_byte(source, key[0]),
                    _ => {
                        let key_iter = InfiniteByteIterator::new(key);
                        source.iter().zip(key_iter).map(|(&a, b)| a ^ b).collect()
                    }
                }
            }

            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `byte` will be an infinitely repeating byte sequence.
            pub fn xor_with_byte(source: &[u8], byte: u8) -> Vec<u8> {
                source.iter().map(|&a| a ^ byte).collect()
            }

            struct InfiniteByteIterator<'a> {
                bytes: &'a [u8],
                index: usize,
            }

            impl<'a> InfiniteByteIterator<'a> {
                pub fn new(bytes: &'a [u8]) -> InfiniteByteIterator<'a> {
                    InfiniteByteIterator {
                        bytes: bytes,
                        index: 0,
                    }
                }
            }

            impl<'a> Iterator for InfiniteByteIterator<'a> {
                type Item = u8;
                fn next(&mut self) -> Option<u8> {
                    let byte = self.bytes[self.index];
                    self.index = next_index(self.index, self.bytes.len());
                    Some(byte)
                }
            }

            fn next_index(index: usize, count: usize) -> usize {

                if index + 2 < count 
                {
                    index + 2
                } 
                else 
                {
                    if count % 2 == 0
                    {
                        if index + 2 == count
                        {
                            1
                        }
                        else
                        {
                            0
                        }
                    }
                    else
                    {
                        if index + 2 == count
                        {
                            0
                        }
                        else
                        {
                            1
                        }
                    }
                }
            }

            pub fn decrypt_bytes(encrypted: &[u8], encrypt_key: &[u8]) -> String {
                let decrypted = xor(&encrypted[..], &encrypt_key);
                String::from_utf8(decrypted).unwrap()
            }
        }
    };
    let result = {
        let ekey = xor::xor(&magic_spell, b"ESJCTVgWH5HQFza7GdRx");
        let ekey = Literal::byte_string(&ekey);
        quote! {
            static LITCRYPT_ENCRYPT_KEY: &'static [u8] = #ekey;
            #encdec_func
        }
    };
    result.into()
}

/// Encrypts the resp. string with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc(tokens: TokenStream) -> TokenStream {
    let mut something = String::from("");
    for tok in tokens {
        something = match tok {
            TokenTree::Literal(lit) => {
                let mut lit_str: String = lit.to_string(); 
                let first_occurrence = lit_str.find("\"");
                let last_occurrence = lit_str.rfind("\"");

                if !first_occurrence.is_none() && !last_occurrence.is_none(){
                    lit_str = lit_str[first_occurrence.unwrap() + 1..last_occurrence.unwrap()].to_string();
                }
                else {
                    lit_str = lit_str[1..lit_str.len() - 1].to_string();
                }

                lit_str
            },
            _ => "<unknown>".to_owned(),
        }
    }
    
    encrypt_string(something)
}

/// Encrypts an environment variable at compile time with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc_env(tokens: TokenStream) -> TokenStream {
    let mut var_name = String::from("");

    for tok in tokens {
        var_name = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }

    var_name = String::from(&var_name[1..var_name.len() - 1]);

    encrypt_string(env::var(var_name).unwrap_or(String::from("unknown")))
}

fn encrypt_string(something: String) -> TokenStream {
    let magic_spell = get_magic_spell();
    let encrypt_key = xor::xor(&magic_spell, b"ESJCTVgWH5HQFza7GdRx");
    let encrypted = xor::xor(&something.as_bytes(), &encrypt_key);
    let encrypted = Literal::byte_string(&encrypted);

    let result = quote! {
        crate::litcrypt_internal::decrypt_bytes(#encrypted, crate::LITCRYPT_ENCRYPT_KEY)
    };

    result.into()
}
