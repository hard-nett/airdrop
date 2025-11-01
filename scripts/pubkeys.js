import { readCsvFile, appendToCsv, readYamlFile, toMarkdownTable, escapeRegExp, toOverviewMarkdownTable, loadProjectAddresses } from "./utils.js";
import { ethers, hexlify } from "ethers";
import { ecrecover, bufferToInt } from "ethereumjs-util";
import fs from 'fs';
import path, { dirname } from 'path'
import yaml from "yaml";
// for each address in each project:
// retrieve latest transaction with signature
//      - if no signature exists, add address to dead/stale csv file 
// recover pubkey using ecrecover
// map addr,pubkey together

async function determineAllPubkeys(provider) {
    const distributionData = await readYamlFile(yamlPath);
    const projectPromises = Object.values(distributionData.projects).map(
        async (proj) => {
            // `proj.csv` holds the CSV path for that project
            const records = await loadProjectAddresses(proj.csv);

            // Turn CSV rows into clean holder objects
            const holders = records
                .map((r) => ({
                    address: r.addr,
                    amount: parseFloat(r.amount),
                }))
                .filter((h) => !isNaN(h.amount));

            for (const holder of holders) {
                const result = await processAddress(holder.address, provider);
                if (result) {
                    await appendToCsv("address_pubkey_map.csv", [
                        result.address,
                        result.pubKey,
                    ]);
                }
            }
        }
    );

    // Wait for every project to finish
    await Promise.all(projectPromises);
    console.log("✅ Finished. Check dead_addresses.csv & address_pubkey_map.csv");


}
/* ------------------------------------------------------------
   Core logic for a single address
   ------------------------------------------------------------ */
async function processAddress(address, provider) {
    // 1️⃣ Get transaction history – ethers v6 `provider.getHistory`
    const history = await provider.getHistory(address);
    if (!history || history.length === 0) {
        // No tx → dead / stale address
        await appendToCsv("dead_addresses.csv", [address]);
        return null;
    }

    const tx = history[history.length - 1]; // history is chronological
    if (!tx?.r || !tx?.s || !tx?.v) {
        // Somehow missing signature data – treat as dead
        await appendToCsv("dead_addresses.csv", [address]);
        return null;
    }

    const pubKey = hexlify(ecrecover(tx.hash, bufferToInt(tx.v), tx.r, tx.s));

    return { address, pubKey };
}

export { processAddress, determineAllPubkeys }