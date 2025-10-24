#!/bin/sh

headstash_generate:
    cd scripts && node main.js -10

# generates all genesis headstash data, using final output
genesis_sinsemilla:
    cd scripts && node main.js -10 && cd ../zk-crates && cargo run --bin create_merkle -- data/genesis_sinsemilla.json

gen_my_notes:
    cd zk-crates && cargo run --bin create_genesis_notes -- ./data/genesis_sinsemilla.json 0x0000000000000000000000000000000000000000
