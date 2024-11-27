import fs from 'fs';

import { processSacNFTdata, encodeAddrs } from "./solana-utils.js";
import { analyzeHeadstashDistribution } from "./analyze-headstash-dist.js";
import { processExportedState } from './exported-state.js';
import { processHeadstashDistributions } from './headstash-scripts.js';
import { processGenesisDistribution } from './genesis-script.js';


// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Invalid option.');
} else if (args[0] === '-1') {
    fs.readFile('../headstash/communities/sac.json', 'utf8', (err, data) => {
        if (err) {
            console.error(err);
        } else {
            processSacNFTdata(data);
        }
    });
} else if (args[0] === '-2') {
    let inputFile = "../headstash/communities/stoned-ape-club/sac-w-tokens.csv";
    let outputFile = "../headstash/communities/stoned-ape-club/sac-w-tokens-encoded.csv";
    encodeAddrs(inputFile, outputFile);
} else if (args[0] === '-3') {
    // Genesis file scripts
    processGenesisDistribution().catch(console.error);
} else if (args[0] === '-4') {
    // Headstash script
    processHeadstashDistributions().catch(console.error);
} else if (args[0] === '-5') {
    processExportedState()
} else if (args[0] === '-6') {
    analyzeHeadstashDistribution()
} else {
    console.error('Invalid option.');
}