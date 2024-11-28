// Genesis script that creates a single file containing all of the balances and distributions  for gaia & btsg holders
//  1. convert addrs to represent terp bech32 prefix 
//  2. sum together duplicate values for addrs, append points expected for addr based on requirements to csv

import fs from 'fs';
import csv from 'csv-parser';
import { bech32 } from 'bech32'

// File paths
const genesisDistFile = '../genesis/scripts-data/final_output.csv';
const totalPointsDist = '../genesis/scripts-data/total-points.csv';
const patchedDist = '../genesis/scripts-data/patched-distribution.csv';
const pointsDist = '../genesis/scripts-data/points_distribution.csv';
const files = [
    "../genesis/bcna_delegators.csv",
    "../genesis/gaia.csv",
    "../genesis/scavenger_hunt.csv",
    "../genesis/terp_og.csv",
];


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

/// Token distribution constants
const totalSupply = 420000000;
const gaiaPercSupply = 0.061152;
const bcnaPercSupply = 0.01911;

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

// Read and parse CSV files
function readCSV(filePath) {
    return new Promise((resolve, reject) => {
        const results = [];
        fs.createReadStream(filePath)
            .pipe(csv())
            .on('data', (data) => results.push(data))
            .on('end', () => resolve(results))
            .on('error', reject);
    });
}

// Aggregate and process CSV files
async function processGenesisDistribution() {
    let gaiaData = await readCSV(files[1]);
    let bcnaData = await readCSV(files[0]);

    let result = [];

    // Step 1: calculate Gaia points based on balances
    let gaiaBalances = gaiaData.reduce((acc, row) => {
        let addr = row.address;
        let balance = parseFloat(row.balance);
        let points = getPoints(balance, atomPoints);
        addr = convertToTerpAddress(addr);  // Convert to 'terp' format

        acc[addr] = acc[addr] || { balance: 0, points: 0 };
        acc[addr].balance += balance;
        acc[addr].points = points;
        return acc;
    }, {});

    // Step 2: Process BCNA data to assign points based on balance
    let bcnaBalances = bcnaData.reduce((acc, row) => {
        let addr = row.address;
        let balance = parseFloat(row.balance);
        let points = getPoints(balance, bcnaPoints);
        addr = convertToTerpAddress(addr);  // Convert to 'terp' format

        acc[addr] = acc[addr] || { balance: 0, points: 0 };
        acc[addr].balance += balance;
        acc[addr].points = points;
        return acc;
    }, {});

    // Step 3: Merge data from both sources and calculate combined points
    let totalGaiaPoints = 0;
    let totalBcnaPoints = 0;
    // objects to count # of addr in each point range
    let gaiaPointsDistribution = { 1: 0, 2: 0, 3: 0 };
    let bcnaPointsDistribution = { 3: 0, 6: 0, 9: 0 };
    let mergedPointsDistribution = { 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0 };

    // Count Gaia addresses
    for (let addr in gaiaBalances) {
        let gaiaBalance = gaiaBalances[addr];
        if (!bcnaBalances[addr]) {
            gaiaPointsDistribution[gaiaBalance.points]++;
        }
    }

    // Count BCNA addresses
    for (let addr in bcnaBalances) {
        let bcnaBalance = bcnaBalances[addr];
        if (!gaiaBalances[addr]) {
            bcnaPointsDistribution[bcnaBalance.points]++;
        }
    }
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

    // Create the CSV content with a header row
    let csvContent = 'Address,Gaia Balance,BCNA Balance,Gaia Points,BCNA Points,Points,Tokens\n';
    result.forEach(row => {
        csvContent += `${row.address},${row.gaiaBalance},${row.bcnaBalance},${row.gaiaPoints},${row.bcnaPoints},${row.points},${row.tokens}\n`;
    });

    // Write the sorted CSV content to the file
    fs.writeFileSync(genesisDistFile, csvContent, 'utf-8');
    console.log(`Final CSV generated: ${genesisDistFile}`);

    // Step 5: Write total points for each project to a new file
    let totalPointsContent = `Project,Total Points,Tokens Per Point,Total Tokens\n`;
    const gaiaTokensPerPoint = totalSupply * gaiaPercSupply / totalGaiaPoints;
    const bcnaTokensPerPoint = totalSupply * bcnaPercSupply / totalBcnaPoints;
    totalPointsContent += `Gaia,${totalGaiaPoints},${gaiaTokensPerPoint},${totalSupply * gaiaPercSupply}\n`;
    totalPointsContent += `BCNA,${totalBcnaPoints},${bcnaTokensPerPoint},${totalSupply * bcnaPercSupply}\n`;
    fs.writeFileSync(totalPointsDist, totalPointsContent, 'utf-8');
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
    fs.writeFileSync(pointsDist, pointsDistributionContent, 'utf-8');
    console.log(`Points distribution file generated: ${pointsDist}`);

}


function checkAddresses() {
    // load state export data
    const zeroSeqAccountsJson = '../genesis/scripts-data/updated_zero_sequence_accounts.json'
    const nonZeroSeqAccountsJson = '../genesis/scripts-data/updated_greater_zero_sequence_accounts.json'
    const zeroSeqData = JSON.parse(fs.readFileSync(zeroSeqAccountsJson, 'utf8'));
    const nonZeroSeqData = JSON.parse(fs.readFileSync(nonZeroSeqAccountsJson, 'utf8'));
    // parse into account array
    const zeroSeqAccounts = zeroSeqData.app_state.auth.accounts;
    const nonZeroSeqAccounts = nonZeroSeqData.app_state.auth.accounts;

    // merge into single object
    const accounts = [...zeroSeqAccounts, ...nonZeroSeqAccounts];
    let csvContent = 'Address,Points,New Allocation,Original Vesting Amount\n';

    let totalGaiaPoints = 0;
    let totalBcnaPoints = 0;
    fs.createReadStream(totalPointsDist)
        .pipe(csv())
        .on('data', (row) => {
            if (row['Project'] === 'Gaia') {
                totalGaiaPoints = parseInt(row['Total Points']);
            } else if (row['Project'] === 'BCNA') {
                totalBcnaPoints = parseInt(row['Total Points']);
            }
        })
        .on('end', () => {
            fs.createReadStream(genesisDistFile)
                .pipe(csv())
                .on('data', (row) => {
                    // grab address, gaia points, bcna points, total points
                    const address = row['Address'];
                    const points = parseInt(row['Points']);
                    const gaiaPoints = parseInt(row['Gaia Points']);
                    const bcnaPoints = parseInt(row['BCNA Points']);

                    // find address from final_output in exported state
                    const account = accounts.find((acc) => acc.address === address);
                    if (!account) {
                        console.log(`Address ${address} not found in accounts`);
                        return;
                    }

                    if (!points) {
                        console.log(`Address ${address} has invalid points`);
                        return;
                    }


                    // calculate new allocation from points and percentDistribution
                    // this is calcualted by ((% tokens allocated to project * total supply) / total points allocated for project) * points
                    const gaiaAllocation = ((gaiaPercSupply * totalSupply) / totalGaiaPoints) * gaiaPoints;
                    console.log(`${address} in Gaia with  ${gaiaPoints} Points gets ${gaiaAllocation}TERP`);
                    const bcnaAllocation = ((bcnaPercSupply * totalSupply) / totalBcnaPoints) * bcnaPoints;
                    console.log(`${address} in BCNA with  ${bcnaPoints} Points gets ${bcnaAllocation}TERP`);
                    const expectedAllocation = gaiaAllocation + bcnaAllocation;

                    csvContent += `${address},${points},${expectedAllocation.toFixed(6)},${account.original_vesting_amount}\n`;
                })
                .on('end', () => {
                    // Write the CSV content to the file

                    fs.writeFileSync(patchedDist, `Address,Points,New Allocation,Original Vesting Amount\n${csvContent}`, 'utf-8');
                    console.log(`CSV file processed and output written to ${patchedDist}`);
                });
        });
}

export { processGenesisDistribution, checkAddresses }