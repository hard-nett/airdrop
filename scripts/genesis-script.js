// Genesis script that creates a single file containing all of the balances and distributions  for gaia & btsg holders
//  1. convert addrs to represent terp bech32 prefix 
//  2. sum together duplicate values for addrs, append points expected for addr based on requirements to csv

import fs from 'fs';
import csv from 'csv-parser';
import path from 'path';
import { bech32 } from 'bech32'

// File paths
let files = [
    "../genesis/bcna_delegators.csv",
    "../genesis/gaia.csv",
    "../genesis/scavenger_hunt.csv",
    "../genesis/terp_og.csv",
];

// Point system based on balance thresholds for Gaia and BCNA
const atomPoints = [
    { points: 1, min: 0, max: 56290873.26 }, // 0th - 74th percentile
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
async function processFiles() {
    let gaiaData = await readCSV(files[1]);
    let bcnaData = await readCSV(files[0]);

    let result = [];

    // Step 1: Process Gaia data to assign points based on balance
    let gaiaBalances = gaiaData.reduce((acc, row) => {
        let addr = row.address;
        let balance = parseFloat(row.balance);
        let points = getPoints(balance, atomPoints);

        // Convert the address to Bech32 format before storing it in the accumulator
        addr = convertToTerpAddress(addr);  // Convert to 'terp' format

        acc[addr] = acc[addr] || { balance: 0, points: 0 };
        acc[addr].balance += balance;
        acc[addr].points = Math.max(acc[addr].points, points); // Take max points for multiple entries
        return acc;
    }, {});

    // Step 2: Process BCNA data to assign points based on balance
    let bcnaBalances = bcnaData.reduce((acc, row) => {
        let addr = row.address;
        let balance = parseFloat(row.balance);
        let points = getPoints(balance, bcnaPoints);

        // Convert the address to Bech32 format before storing it in the accumulator
        addr = convertToTerpAddress(addr);  // Convert to 'terp' format

        acc[addr] = acc[addr] || { balance: 0, points: 0 };
        acc[addr].balance += balance;
        acc[addr].points = Math.max(acc[addr].points, points); // Take max points for multiple entries
        return acc;
    }, {});

    // Step 3: Merge data from both sources and calculate combined points
    for (let addr in gaiaBalances) {
        let gaiaBalance = gaiaBalances[addr];
        let bcnaBalance = bcnaBalances[addr] || { balance: 0, points: 0 };

        // Attempt to find a matching merged point combination
        let mergedPoint = mergedPoints.find(mp => mp.bcna === bcnaBalance.points && mp.atom === gaiaBalance.points);

        // If no matching combination is found, retain the higher points from Gaia or BCNA
        let combinedPoints = 0;
        if (mergedPoint) {
            combinedPoints = mergedPoint.points;  // If a match, take the merged points
        } else {
            // If no match, retain the max points from either Gaia (atom) or BCNA (bcna)
            combinedPoints = Math.max(gaiaBalance.points, bcnaBalance.points);
        }
        // Add to result
        result.push({
            address: addr,  // The address is already in 'terp' Bech32 format
            gaiaBalance: gaiaBalance.balance,
            bcnaBalance: bcnaBalance.balance,
            points: combinedPoints
        });
    }


    // Step 4: Write final output to CSV 
    const outputFile = '../genesis/final_output.csv';
    result.sort((a, b) => b.points - a.points);

    // Create the CSV content with a header row
    let csvContent = 'Address,Gaia Balance,BCNA Balance,Points\n';
    result.forEach(row => {
        csvContent += `${row.address},${row.gaiaBalance},${row.bcnaBalance},${row.points}\n`;
    });

    // Write the sorted CSV content to the file
    fs.writeFileSync(outputFile, csvContent, 'utf-8');
    console.log(`Final CSV generated: ${outputFile}`);
}

export { processFiles }