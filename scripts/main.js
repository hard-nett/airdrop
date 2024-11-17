import fs from 'fs';

import { processData, encodeAddrs } from "./solana-utils.js";

// Call the function


// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Invalid option.');
} else if (args[0] === '-1') {
    fs.readFile('../headstash/communities/sac.json', 'utf8', (err, data) => {
        if (err) {
            console.error(err);
        } else {
            processData(data);
        }
    });
} else if (args[0] === '-2') {
    let inputFile = "../headstash/communities/stoned-ape-club/sac-w-tokens.csv";
    let outputFile = "../headstash/communities/stoned-ape-club/sac-w-tokens-encoded.csv";
    encodeAddrs(inputFile, outputFile);
} else if (args[0] === '-3') {
    instantiate_test_contract();
} else {
    console.error('Invalid option.');

}