// Compile this example code and check the compiled output with:
// $ strings ./target/debug/examples/simple | grep Voldemort
// the encrypted one will not print anything (just blank).

#[macro_use]
extern crate litcrypt2;

extern crate alloc;

use_litcrypt!();

fn main() {
    // uncomment this for plain (non pre-compile-encrypted string)
    // println!("his name is: {}", "Voldemort");
    println!("his name is: {}", lc!("Voldemort"));
}
