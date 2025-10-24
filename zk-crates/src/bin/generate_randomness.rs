use zk_crates::randomness::ultra_secure_random;

fn main() {
    let data = ultra_secure_random();
    println!("Randomness: {:#?}", hex::encode(data));
}
