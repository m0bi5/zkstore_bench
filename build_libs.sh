cd ./crypto/ecies
cargo build --release
cd ../..
mv ./crypto/ecies/target/x86_64-unknown-linux-gnu/release/librust_ecies.so ./blockchain/libs/rust_ecies.so

cd ./crypto/schnorr
cargo build --release
cd ../..
mv ./crypto/schnorr/target/x86_64-unknown-linux-gnu/release/librust_schnorr.so ./blockchain/libs/rust_schnorr.so

cd ./crypto/mimc
cargo build --release
cd ../..
mv ./crypto/mimc/target/x86_64-unknown-linux-gnu/release/librust_mimc.so ./blockchain/libs/rust_mimc.so

cd ./crypto/merkle_tree
cargo build --release
cd ../..
mv ./crypto/merkle_tree/target/x86_64-unknown-linux-gnu/release/librust_merkle_tree.so ./blockchain/libs/rust_merkle_tree.so

cd ./crypto/circuits
cargo build --release
cd ../..
mv ./crypto/circuits/target/x86_64-unknown-linux-gnu/release/librust_circuits.so ./blockchain/libs/rust_circuits.so