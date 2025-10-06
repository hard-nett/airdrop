import fs from 'fs';

import { processSacNFTdata, encodeAddrs } from "./solana-utils.js";
import { processGenesisState, calculateTokenDifference, summarizeAllResults, summarizeScavengerHunt } from './exported-state.js';
import { processHeadstashDistributions } from './headstash-scripts.js';
import { processGenesisDistribution, checkAddresses } from './genesis-script.js';

import { SAC_INPUT_CSV_PATH, SAC_OUTPUT_CSV_PATH, SAC_JSON_PATH } from './constants.js';

// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Invalid option.');
} else if (args[0] === '-1') {
    processGenesisDistribution().catch(console.error);
    processGenesisState();
    checkAddresses();
    calculateTokenDifference();
    summarizeAllResults();
} else if (args[0] === '-2') {
    processGenesisDistribution().catch(console.error);
} else if (args[0] === '-3') {
    processGenesisState();
} else if (args[0] === '-4') {
    checkAddresses();
} else if (args[0] === '-5') {
    calculateTokenDifference();
} else if (args[0] === '-6') {
    summarizeAllResults();
    summarizeScavengerHunt();
} else if (args[0] === '-7') {
    processHeadstashDistributions().catch(console.error);
} else if (args[0] === '-8') {
    // reads json of solana NFT holder snapshot, creates csv with # of tokens unique addrs hold
    fs.readFile(SAC_JSON_PATH, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
        } else {
            processSacNFTdata(data);
        }
    });
    // base64-encodes solana addresses in format that will be used to verify offline signature
    encodeAddrs(SAC_INPUT_CSV_PATH, SAC_OUTPUT_CSV_PATH);
} else {
    console.error('Invalid option.');
}