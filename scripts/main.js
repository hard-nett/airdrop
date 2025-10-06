import fs from 'fs';

import { processSacNFTdata, encodeAddrs } from "./solana-utils.js";
import { processExportedState, calculateTokenDifference, summarizeAllResults, summarizeScavengerHunt } from './exported-state.js';
import { processHeadstashDistributions } from './headstash-scripts.js';
import { processGenesisDistribution, checkAddresses } from './genesis-script.js';

const SAC_JSON_PATH = '../headstash/communities/sac.json';
const SAC_INPUT_CSV_PATH = '../headstash/communities/stoned-ape-club/sac-w-tokens.csv';
const SAC_OUTPUT_CSV_PATH = '../headstash/communities/stoned-ape-club/sac-w-tokens-encoded.csv';


// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Invalid option.');
} else if (args[0] === '-1') {
    processGenesisDistribution().catch(console.error);
    processExportedState();
    checkAddresses();
    calculateTokenDifference();
    summarizeAllResults();
} else if (args[0] === '-2') {
    processGenesisDistribution().catch(console.error);
} else if (args[0] === '-3') {
    processExportedState();
} else if (args[0] === '-4') {
    checkAddresses();
} else if (args[0] === '-5') {
    calculateTokenDifference();
} else if (args[0] === '-5') {
    summarizeAllResults();
    summarizeScavengerHunt()
} else if (args[0] === '-6') {
    processHeadstashDistributions().catch(console.error);
} else if (args[0] === '-7') {
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