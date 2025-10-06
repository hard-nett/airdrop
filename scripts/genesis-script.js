// Genesis script that creates a single file containing all of the balances and distributions for gaia & btsg holders
//  1. convert addrs to represent terp bech32 prefix 
//  2. calculate points for each unique address.

import fs from 'fs';
import csv from 'csv-parser';
import { bech32 } from 'bech32'
import { readCsvFile } from './utils.js';

import { RAW_SNAPSHOT_FILES, GENESIS_DISTRIBUTION_FILE, INACTIVE_ACCOUNT_FILE, ACTIVE_ACCOUNTS_FILE, PATCHED_DISTRIBUTION_FILE, GAIA_PERC_SUPPLY, TOTAL_SUPPLY,BCNA_PERC_SUPPLY, TOTAL_POINTS_FILE, POINTS_SUMMARY_FILE } from './constants.js';

// Point system based on balance percentiles for Gaia and BCNA
const atomPoints = [
    { points: 1, min: 1, max: 56290873.26, tpp: 119.131693 }, // 1st - 74th percentile
    { points: 2, min: 56290873.26, max: 581059663.70, tpp: 119.131693 }, // 75th - 95th percentile
    { points: 3, min: 581059663.70, max: 11695142809644.00, tpp: 119.131693 } // 96th - 100th percentile
];

const bcnaPoints = [
    { points: 3, min: 0, max: 56104789.25, tpp: 5790.90909 }, // 0th - 25th percentile
    { points: 6, min: 56104789.25, max: 3835224107.75, tpp: 5790.90909 }, // 26th - 75th percentile
    { points: 9, min: 3835224107.75, max: 32910049646754.00, tpp: 5790.90909 } // 76th - 100th percentile
];

export const mergedPoints = [
    { points: 4, bcna: 3, atom: 1, tpp: 1477.51019575 },
    { points: 5, bcna: 3, atom: 2, tpp: 1205.8344952 },
    { points: 6, bcna: 3, atom: 3, tpp: 1024.7173615 },
    { points: 7, bcna: 6, atom: 1, tpp: 1671.564267 },
    { points: 8, bcna: 6, atom: 2, tpp: 1477.510195 },
    { points: 9, bcna: 6, atom: 3, tpp: 1326.579251 },
    { points: 10, bcna: 9, atom: 1, tpp: 1749.185896 },
    { points: 11, bcna: 9, atom: 2, tpp: 1600.999150 },
    { points: 12, bcna: 9, atom: 3, tpp: 1477.510195 },
]



function getPoints(balance, pointsList) {
    for (const point of pointsList) {
        if (balance >= point.min && balance <= point.max) {
            return point.points;
        }
    }
    return 0;
}

function convertToTerpAddress(addr) {
    const decoded = bech32.decode(addr);
    const newPrefix = 'terp';
    const newAddress = bech32.encode(newPrefix, decoded.words);
    return newAddress;
}

function processBalanceData(data, pointValue) {
    return data.reduce((acc, row) => {
        let addr = convertToTerpAddress(row.address); // Convert to 'terp' format
        let balance = parseFloat(row.balance);
        let points = getPoints(balance, pointValue);

        acc[addr] = acc[addr] || { balance: 0, points: 0 };
        acc[addr].balance += balance;
        acc[addr].points = points; // Note: points based on current balance only
        return acc;
    }, {});
}

// Reusable function to count addresses and distribute points
function countAddresses(balances, distribution, exclude = {}) {
    let count = 0;
    for (let addr in balances) {
        if (exclude[addr]) continue; // Skip if in exclude list
        let points = balances[addr].points;
        distribution[points] = (distribution[points] || 0) + 1;
        count++;
    }
    return count;
}


// Aggregate and process CSV files
async function processGenesisDistribution() {
    let gaiaData = await readCsvFile(RAW_SNAPSHOT_FILES[1]);
    let bcnaData = await readCsvFile(RAW_SNAPSHOT_FILES[0]);

    let result = [];

    // Step 1: Calculate Gaia & BCNA based on balances
    let gaiaBalances = processBalanceData(gaiaData, atomPoints);
    let bcnaBalances = processBalanceData(bcnaData, bcnaPoints);


    // Step 3: Merge data from both sources and calculate combined points
    let totalGaiaPoints = 0;
    let totalBcnaPoints = 0;
    let totalGaiaAddrs = 0;
    let totalBcnaAddrs = 0;

    // objects to count # of addr in each point range
    let gaiaPointsDistribution = { 1: 0, 2: 0, 3: 0 };
    let bcnaPointsDistribution = { 3: 0, 6: 0, 9: 0 };
    let mergedPointsDistribution = { 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0 };

    // Count standalone Gaia and BCNA addresses (non-overlapping)
    totalGaiaAddrs = countAddresses(gaiaBalances, gaiaPointsDistribution, bcnaBalances);
    totalBcnaAddrs = countAddresses(bcnaBalances, bcnaPointsDistribution, gaiaBalances);

    // calculate new allocation from points and percentDistribution
    for (let addr in gaiaBalances) {
        let gaiaBalance = gaiaBalances[addr];
        if (bcnaBalances[addr]) {
            let bcnaBalance = bcnaBalances[addr];
            // Attempt to find a matching merged point combination
            let mergedPoint = mergedPoints.find(mp => mp.bcna === bcnaBalance.points && mp.atom === gaiaBalance.points);

            // Calculate combined points
            let combinedPoints = 0;
            if (mergedPoint) {
                combinedPoints = mergedPoint.points;  // If a match, take the merged points
                console.log(mergedPoint)
                mergedPointsDistribution[mergedPoint.points]++;
            } else {
                if (bcnaBalance.points === 0) {
                    combinedPoints = gaiaBalance.points;
                } else if (gaiaBalance.points === 0) {
                    combinedPoints = bcnaBalance.points;
                } else {
                    combinedPoints = Math.max(bcnaBalance.points, gaiaBalance.points);
                }
            }

            let gaiaPointValue = atomPoints.find(ap => ap.points === gaiaBalance.points);
            let gaiaTokens = gaiaPointValue ? gaiaBalance.points * gaiaPointValue.tpp : 0;

            let bcnaPointValue = bcnaPoints.find(bp => bp.points === bcnaBalance.points);
            let bcnaTokens = bcnaPointValue ? bcnaBalance.points * bcnaPointValue.tpp : 0;

            let mergedPointValue = mergedPoints.find(mp => mp.points === combinedPoints);
            let mergedTokens = mergedPointValue ? combinedPoints * mergedPointValue.tpp : 0;

            result.push({
                address: addr,
                gaiaBalance: gaiaBalance.balance,
                bcnaBalance: bcnaBalance.balance,
                gaiaPoints: gaiaBalance.points,
                bcnaPoints: bcnaBalance.points,
                points: combinedPoints,
                tokens: mergedTokens
            });

            totalGaiaPoints += gaiaBalance.points;
            totalBcnaPoints += bcnaBalance.points;
        } else {
            // Add to result
            // For non-merged addresses
            let pointValue = atomPoints.find(ap => ap.points === gaiaBalance.points);
            let tokens = pointValue ? gaiaBalance.points * pointValue.tpp : 0;

            result.push({
                address: addr,
                gaiaBalance: gaiaBalance.balance,
                bcnaBalance: 0,
                gaiaPoints: gaiaBalance.points,
                bcnaPoints: 0,
                points: gaiaBalance.points,
                tokens: tokens
            });

            totalGaiaPoints += gaiaBalance.points;
        }
    }


    // Step 4: Write final output to CSV 
    result.sort((a, b) => b.points - a.points);
    let csvContent = 'Address,Gaia Balance,BCNA Balance,Gaia Points,BCNA Points,Points,Tokens\n';
    result.forEach(row => {
        csvContent += `${row.address},${row.gaiaBalance},${row.bcnaBalance},${row.gaiaPoints},${row.bcnaPoints},${row.points},${row.tokens}\n`;
    });
    fs.writeFileSync(GENESIS_DISTRIBUTION_FILE, csvContent, 'utf-8');
    console.log(`Final CSV generated: ${GENESIS_DISTRIBUTION_FILE}`);

    // Step 5: Count addresses per project and write totals
    const gaiaAddresses = new Set(result.filter(r => r.gaiaPoints > 0).map(r => r.address));
    const bcnaAddresses = new Set(result.filter(r => r.bcnaPoints > 0).map(r => r.address));
    const gaiaAddressCount = gaiaAddresses.size;
    const bcnaAddressCount = bcnaAddresses.size;

    // Step 5: Write total points for each project to a new file
    let totalPointsContent = 'Project,Total Points,Address Count,Tokens Per Point,Total Tokens\n';
    const gaiaTokensPerPoint = TOTAL_SUPPLY * GAIA_PERC_SUPPLY / totalGaiaPoints;
    const bcnaTokensPerPoint = TOTAL_SUPPLY * BCNA_PERC_SUPPLY / totalBcnaPoints;
    totalPointsContent += `Gaia,${totalGaiaPoints},${totalGaiaAddrs},${gaiaTokensPerPoint},${TOTAL_SUPPLY * GAIA_PERC_SUPPLY}\n`;
    totalPointsContent += `BCNA,${totalBcnaPoints},${totalBcnaAddrs},${bcnaTokensPerPoint},${TOTAL_SUPPLY * BCNA_PERC_SUPPLY}\n`; fs.writeFileSync(TOTAL_POINTS_FILE, totalPointsContent, 'utf-8');
    console.log(`Total points file generated: total-points.csv`);


    // Step 6: Write Point distribution 
    let pointsDistributionContent = 'Project,Points,Count\n';
    for (let points in gaiaPointsDistribution) {
        pointsDistributionContent += `Gaia,${points},${gaiaPointsDistribution[points]}\n`;
    }
    for (let points in bcnaPointsDistribution) {
        pointsDistributionContent += `BCNA,${points},${bcnaPointsDistribution[points]}\n`;
    }
    for (let points in mergedPointsDistribution) {
        pointsDistributionContent += `Merged,${points},${mergedPointsDistribution[points]}\n`;
    }
    fs.writeFileSync(POINTS_SUMMARY_FILE, pointsDistributionContent, 'utf-8');
    console.log(`Points distribution file generated: ${POINTS_SUMMARY_FILE}`);
}


function checkAddresses() {
    const zeroSeqData = JSON.parse(fs.readFileSync(INACTIVE_ACCOUNT_FILE, 'utf8'));
    const nonZeroSeqData = JSON.parse(fs.readFileSync(ACTIVE_ACCOUNTS_FILE, 'utf8'));
    // parse into account array
    const zeroSeqAccounts = zeroSeqData.app_state.auth.accounts;
    const nonZeroSeqAccounts = nonZeroSeqData.app_state.auth.accounts;

    // merge into single object
    const accounts = [...zeroSeqAccounts, ...nonZeroSeqAccounts];
    let csvContent = 'Address,Points,New Allocation,Original Allocation\n';

    let totalGaiaPoints = 0;
    let totalBcnaPoints = 0;
    fs.createReadStream(TOTAL_POINTS_FILE)
        .pipe(csv())
        .on('data', (row) => {
            if (row['Project'] === 'Gaia') {
                totalGaiaPoints = parseInt(row['Total Points']);
            } else if (row['Project'] === 'BCNA') {
                totalBcnaPoints = parseInt(row['Total Points']);
            }
        })
        .on('end', () => {
            fs.createReadStream(GENESIS_DISTRIBUTION_FILE)
                .pipe(csv())
                .on('data', (row) => {
                    // grab address, gaia points, bcna points, total points
                    const address = row['Address'];
                    const points = parseInt(row['Points']);
                    const gaiaPoints = parseInt(row['Gaia Points']);
                    const bcnaPoints = parseInt(row['BCNA Points']);

                    // find address from final-output in exported state
                    const account = accounts.find((acc) => acc.address === address);
                    if (!account) {
                        console.log(`Address ${address} not found in accounts`);
                        return;
                    }

                    if (!points) {
                        console.log(`Address ${address} has invalid points`);
                        return;
                    }

                    // calculate new, correct allocation
                    // this is calcualted by ((% tokens allocated to project * total supply) / total points allocated for project) * points
                    const gaiaAllocation = ((GAIA_PERC_SUPPLY * TOTAL_SUPPLY) / totalGaiaPoints) * gaiaPoints;
                    console.log(`${address} in Gaia with  ${gaiaPoints} Points gets ${gaiaAllocation}TERP`);
                    const bcnaAllocation = ((BCNA_PERC_SUPPLY * TOTAL_SUPPLY) / totalBcnaPoints) * bcnaPoints;
                    console.log(`${address} in BCNA with  ${bcnaPoints} Points gets ${bcnaAllocation}TERP`);
                    const expectedAllocation = gaiaAllocation + bcnaAllocation;
                    const originalAllocation = parseFloat(account.original_vesting_amount);
                    if (isNaN(originalAllocation)) {
                        console.error(`Failed to parse original_vesting_amount for address: ${address}, value:`, account.original_vesting_amount);
                        process.exit(1); // Exit with error
                    }
                    const scaledOriginal = originalAllocation / 1_000_000;
                    csvContent += `${address},${points},${expectedAllocation.toFixed(6)},${scaledOriginal.toFixed(6)}\n`;
                })
                .on('end', () => {
                    // Write the CSV content to the file
                    fs.writeFileSync(PATCHED_DISTRIBUTION_FILE, `${csvContent}`, 'utf-8');
                    console.log(`CSV file processed and output written to ${PATCHED_DISTRIBUTION_FILE}`);
                });
        });
}

export { processGenesisDistribution, checkAddresses }