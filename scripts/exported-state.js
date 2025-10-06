import fs from 'fs';
import csv from 'csv-parser';

import { readCsvFile, readJsonFile } from './utils.js';
import { mergedPoints, TOTAL_SUPPLY } from './genesis-script.js';

// inputs
const LIVE_NETWORK_EXPORT_FILE = "../data/genesis.json"
const CALCULATED_GENESIS_DISTRIBUTION_FILE = "../genesis/scripts-data/final-output.csv"
const PATCHED_DISTRIBUTION_FILE = "../genesis/scripts-data/patched-distribution.csv"
const SCAVENGER_HUNT_FILE = "../genesis/scavenger_hunt.csv"
const TERPOG_FILE = "../genesis/terp_og.csv"

// outputs
const INACTIVE_ACCOUNT_OUTPUT = "../genesis/scripts-data/accounts-inactive.json"
const ACTIVE_ACCOUNTS_OUTPUT = "../genesis/scripts-data/accounts-active.json"
const TOKEN_DIFF_OUTPUT = "../genesis/scripts-data/token-differences.csv"
const SUMMARY_OUTPUT = "../genesis/scripts-data/summary.json"


// - parse genesis file to get original distributions, run calculations on these. 
// - parse export file to determine which addresses are active and which ones are not. 
async function processExportedState() {
    fs.readFile(LIVE_NETWORK_EXPORT_FILE, (err, data) => {
        if (err) {
            console.error(err);
            return;
        }
        // Read the CSV file
        const genesisAccounts = [];
        fs.createReadStream(CALCULATED_GENESIS_DISTRIBUTION_FILE)
            .pipe(csv())
            .on('data', (row) => {
                genesisAccounts.push(row);
            })
            .on('end', () => {
                const updatedZeroSequenceAccounts = [];
                const updatedGreaterZeroSequenceAccounts = [];
                JSON.parse(data).app_state.auth.accounts.filter((account) => {
                    return genesisAccounts.some((genesisAccount) => genesisAccount.address === account.address);
                }).forEach((account) => {
                    if (account.base_vesting_account) {
                        // Separate accounts by sequence
                        const accountInfo = {
                            account_number: account.base_vesting_account.base_account.account_number,
                            address: account.base_vesting_account.base_account.address,
                            sequence: account.base_vesting_account.base_account.sequence,
                            original_vesting_amount: account.base_vesting_account.original_vesting[0].amount
                        };

                        if (account.base_vesting_account.base_account.sequence === '0') {
                            updatedZeroSequenceAccounts.push(accountInfo);
                        } else {
                            updatedGreaterZeroSequenceAccounts.push(accountInfo);
                        }
                    }
                });
                updatedGreaterZeroSequenceAccounts.sort((a, b) => parseInt(b.sequence) - parseInt(a.sequence));
                const updatedZeroSequenceAccountsJson = { app_state: { auth: { accounts: updatedZeroSequenceAccounts } } };
                fs.writeFileSync(INACTIVE_ACCOUNT_OUTPUT, JSON.stringify(updatedZeroSequenceAccountsJson, null, 2));
                const updatedGreaterZeroSequenceAccountsJson = { app_state: { auth: { accounts: updatedGreaterZeroSequenceAccounts } } };
                fs.writeFileSync(ACTIVE_ACCOUNTS_OUTPUT, JSON.stringify(updatedGreaterZeroSequenceAccountsJson, null, 2));
            });
    });
}

const readGenesisDistribution = async () => {
    return new Promise((resolve, reject) => {
        const genesisDistribution = [];
        fs.createReadStream(CALCULATED_GENESIS_DISTRIBUTION_FILE)
            .pipe(csv())
            .on('data', (row) => {
                genesisDistribution.push({
                    address: row.Address,
                    tokens: parseInt(row.Tokens),
                });
            })
            .on('end', () => {
                resolve(genesisDistribution);
            })
            .on('error', (error) => {
                reject(error);
            });
    });
};


const summarizeAllResults = async () => {
    const csvData = await readCsvFile(PATCHED_DISTRIBUTION_FILE); // assuming this function exists
    const totalSupply = BigInt(Math.round(parseFloat(TOTAL_SUPPLY) * 1e6)); // scaled
    const SCALE = 1e6;

    // Count unique addresses (assuming 'Address' is the column name)
    const uniqueAddresses = new Set(csvData.map(row => row['Address'])).size;

    // Calculate totals from CSV using scaled BigInts
    const totals = csvData.reduce(
        (acc, row) => {
            const original = Math.round(parseFloat(row['Original Allocation']) * SCALE);
            const updated = Math.round(parseFloat(row['New Allocation']) * SCALE);
            acc.originalAllocation += BigInt(original);
            acc.newAllocation += BigInt(updated);

            return acc;
        },
        { originalAllocation: BigInt(0), newAllocation: BigInt(0) }
    );

    // Calculate percentages relative to total supply
    const originalPercentage = (totals.originalAllocation * 10000n) / totalSupply;
    const newPercentage = (totals.newAllocation * 10000n) / totalSupply;

    const summary = {
        unique_address_count: uniqueAddresses,
        distribution: {
            original: {
                totalAmount: (Number(totals.originalAllocation) / SCALE).toFixed(6),
                percentage_of_supply: Number(originalPercentage) / 100,
            },
            new: {
                totalAmount: (Number(totals.newAllocation) / SCALE).toFixed(6),
                percentage_of_supply: Number(newPercentage) / 100

            }
        },
        // allocation_delta: {
        //     description: 'Difference between intended and actual airdrop distribution',
        //     additional_required: {
        //         value: totalAdditional,
        //         display: `${totalAdditional.toFixed(6)} TERP`,
        //         note: 'TERP that should have been distributed but was not'
        //     },
        //     excess_overdistributed: {
        //         value: totalExcess,
        //         display: `${totalExcess.toFixed(6)} TERP`,
        //         note: 'Over-allocated TERP not clawed back'
        //     },
        //     net_impact: {
        //         value: totalAdditional - totalExcess,
        //         display: `${(totalAdditional - totalExcess).toFixed(6)} TERP`,
        //         note: 'Net shortfall (+) or surplus (-)'
        //     }
        // },
    };

    fs.writeFileSync(SUMMARY_OUTPUT, JSON.stringify(summary, null, 2))
};


// Calculate token difference
const summarizeScavengerHunt = async () => {
    const scavengerHunt = await readCsvFile(SCAVENGER_HUNT_FILE);
    const terpOg = await readCsvFile(TERPOG_FILE);

    const seenAddresses = new Set(); // Track unique addresses
    let totalPoints = 0;
    let totalOriginalAllocation = 0n;

    // Helper to safely process rows from a file
    const processFile = (rows, sourceName) => {
        for (const row of rows) {
            const addr = row.Address;
            const points = row.Points;
            const allocationStr = row["Original Allocation"];

            if (!addr) {
                console.warn(`Skipping row in ${sourceName}: missing Address`, row);
                continue;
            }

            if (!allocationStr) {
                console.warn(`Skipping row in ${sourceName}: missing 'Original Allocation'`, row);
                continue;
            }

            if (seenAddresses.has(addr)) {
                console.debug(`Duplicate address skipped: ${addr}`);
                continue; // Skip if already counted
            }

            seenAddresses.add(addr);
            totalPoints += parseInt(points, 10) || 0;
            totalOriginalAllocation += BigInt(allocationStr);
        }
    };

    processFile(scavengerHunt, "ScavengerHunt");
    processFile(terpOg, "TerpOG");
    // Convert microdenom to base denom with 6 decimal places
    const fullDenom = (Number(totalOriginalAllocation) / 1e6).toFixed(6);

    let result = {
        totalAddresses: scavengerHunt.length,
        validAddresses: scavengerHunt.filter(row => row["Original Allocation"]).length,
        totalPoints,
        totalOriginalAllocation: fullDenom
    }
    console.log("\n--- Scavenger Hunt Summary ---");
    console.log(`Total Addresses  : ${result.totalAddresses}`);
    console.log(`Total Points       : ${result.totalPoints}`);
    console.log(`Total Allocation   : ${result.totalOriginalAllocation} TERP`);
    console.log("--------------------------------\n");
};

// Calculate token difference
const calculateTokenDifference = async () => {
    const genesisDistribution = await readGenesisDistribution();
    const zeroSequenceAccounts = await readJsonFile(INACTIVE_ACCOUNT_OUTPUT);
    const originalAllocations = await readJsonFile(ACTIVE_ACCOUNTS_OUTPUT);
    // const nonZeroSequenceAccounts = await readJsonFile(ACTIVE_ACCOUNTS_OUTPUT);
    const output = [];

    const processAccounts = (accounts) => {
        accounts.map((account) => {
            const matched = genesisDistribution.find((g) => g.address === account.address);
            if (!matched) return null;
            const tokenDifference = matched.tokens - account.original_vesting_amount / 1e6;
            return { address: account.address, tokenDifference };
        })
            .filter(Boolean).sort((a, b) => b.tokenDifference - a.tokenDifference)
            .forEach(({ address, tokenDifference }) => {
                output.push(`${address},${tokenDifference}`);
            });
    };


    output.push('Address,Token Difference'); // Header row

    processAccounts(zeroSequenceAccounts.app_state.auth.accounts);
    processAccounts(nonZeroSequenceAccounts.app_state.auth.accounts);

    fs.writeFileSync(TOKEN_DIFF_OUTPUT, output.join('\n'));
};



//   - active account multipler:
//     - 1-10 tx: 10,000 THIOL, 1,000 TERP
//     - 11-100 tx: 25,000 THIOL, 2,500 TERP
//     - 100+: 50,000 THIOL, 5,000 TERP
//   - active validators multiplers:
//     - all existing validators:
//       - 4,200 TERP & THIOL

export { processExportedState, calculateTokenDifference, summarizeAllResults, summarizeScavengerHunt }