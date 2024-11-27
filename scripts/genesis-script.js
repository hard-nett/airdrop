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
    { points: 1, min: 1, max: 56290873.26 }, // 1st - 74th percentile
    { points: 2, min: 56290873.26, max: 581059663.70 }, // 75th - 95th percentile
    { points: 3, min: 581059663.70, max: 11695142809644.00 } // 96th - 100th percentile
];

const bcnaPoints = [
    { points: 3, min: 1, max: 56104789.25 }, // 1st - 25th percentile
    { points: 6, min: 56104789.25, max: 3835224107.75 }, // 26th - 75th percentile
    { points: 9, min: 3835224107.75, max: 32910049646754.00 } // 76th - 100th percentile
];

const mergedPoints = [
    { points: 4, bcna: 3, atom: 1 },
    { points: 5, bcna: 3, atom: 2 },
    { points: 6, bcna: 3, atom: 3 },
    { points: 7, bcna: 6, atom: 1 },
    { points: 8, bcna: 6, atom: 2 },
    { points: 9, bcna: 6, atom: 3 },
    { points: 10, bcna: 9, atom: 1 },
    { points: 11, bcna: 9, atom: 2 },
    { points: 12, bcna: 9, atom: 3 },
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

    // calculate new allocation from points and percentDistribution
    for (let addr in gaiaBalances) {
        let gaiaBalance = gaiaBalances[addr];
        let bcnaBalance = bcnaBalances[addr] || { balance: 0, points: 0 };

        // Attempt to find a matching merged point combination
        let mergedPoint = mergedPoints.find(mp => mp.bcna === bcnaBalance.points && mp.atom === gaiaBalance.points);

        // Calculate combined points
        let combinedPoints = 0;
        if (mergedPoint) {
            combinedPoints = mergedPoint.points;  // If a match, take the merged points
        } else {
            if (bcnaBalance.points === 0) {
                combinedPoints = gaiaBalance.points;
            } else if (gaiaBalance.points === 0) {
                combinedPoints = bcnaBalance.points;
            } else {
                combinedPoints = Math.max(bcnaBalance.points, gaiaBalance.points);
            }
        }

        // Add to result
        result.push({
            address: addr,
            gaiaBalance: gaiaBalance.balance,
            bcnaBalance: bcnaBalance.balance,
            gaiaPoints: gaiaBalance.points,
            bcnaPoints: bcnaBalance.points,
            points: combinedPoints
        });

        totalGaiaPoints += gaiaBalance.points;
        totalBcnaPoints += bcnaBalance.points;
    }

    // Step 4: Write final output to CSV 
    result.sort((a, b) => b.points - a.points);

    // Create the CSV content with a header row
    let csvContent = 'Address,Gaia Balance,BCNA Balance,Gaia Points,BCNA Points,Points\n';
    result.forEach(row => {
        csvContent += `${row.address},${row.gaiaBalance},${row.bcnaBalance},${row.gaiaPoints},${row.bcnaPoints},${row.points}\n`;
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

    countPoints();
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

function countPoints() {
    const gaiaPoints = { '1': 0, '2': 0, '3': 0 };
    const bcnaPoints = { '0': 0, '3': 0, '6': 0, '9': 0 };
    const totalPoints = {};

    // buggy, but total seems to work.
    fs.createReadStream(genesisDistFile)
        .pipe(csv())
        .on('data', (data) => {
            const gaiaPoint = data['Gaia Points'];
            const bcnaPoint = data['BCNA Points'];
            const points = data['Points'];

            if (gaiaPoint) {
                gaiaPoints[gaiaPoint]++;
            }

            if (bcnaPoint) {
                bcnaPoints[bcnaPoint]++;
            }

            if (!totalPoints[points]) {
                totalPoints[points] = 0;
            }
            totalPoints[points]++;
        })
        .on('end', () => {
            const gaiaResults = Object.keys(gaiaPoints).map((key) => `Gaia,${key},${gaiaPoints[key]}`).join('\n');
            const bcnaResults = Object.keys(bcnaPoints).map((key) => `BCNA,${key},${bcnaPoints[key]}`).join('\n');
            const totalResults = Object.keys(totalPoints).map((key) => `Total,${key},${totalPoints[key]}`).join('\n');

            const csvContent = `Points Type,Points Value,Count\n${gaiaResults}\n${bcnaResults}\n${totalResults}`;

            fs.writeFileSync(pointsDist, csvContent);
            console.log('Results written to points_distribution.csv');
        });
}

export { processGenesisDistribution, checkAddresses }