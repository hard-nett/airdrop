// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import csv from 'csv-parser';

// PERCENTILE RANGE POINTS
let bbPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 87th percentile
    { points: 2, min: 2, max: 12 }, // 26th - 75th percentile
    { points: 3, min: 13, max: 790 } // 76th - 100th percentile
]
let budsPoints = [
    { points: 1, min: 1, max: 1 },  // 1st - 25th percentile
    { points: 2, min: 2, max: 8 },  // 26th - 75th percentile
    { points: 3, min: 9, max: 289 } // 76th - 100th percentile
]
let cbPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 68th percentile
    { points: 2, min: 2, max: 3 }, // 69th - 93rd percentile
    { points: 3, min: 4, max: 9 } // 94th - 100th percentile
]
let cccPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
    { points: 2, min: 2, max: 6 }, // 66th - 95th percentile
    { points: 3, min: 7, max: 300 } // 96th - 100th percentile
]
let chtPoints = [
    { points: 1, min: 2957.53, max: 29907.26 }, // 15th - 60th percentile
    { points: 2, min: 29982.06, max: 144068.86 }, // 61stth - 83rd percentile
    { points: 3, min: 146172.26, max: 1006878.94 }, // 84th - 95thpercentile
    { points: 4, min: 1016322.14, max: 52230931.14 } // 96th - 100th percentile
]

let ggPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
    { points: 2, min: 2, max: 8 }, // 66th - 92th percentile
    { points: 3, min: 9, max: 66 } // 93rd - 100th percentile
]
let hlkPoints = [
    { points: 1, min: 1, max: 9 },    // 1st - 89th percentile
    { points: 2, min: 10, max: 45 },  // 90th - 99th percentile
    { points: 3, min: 116, max: 116 } // 100th percentile
]

let rebudPoints = [
    { points: 1, min: 1, max: 10 },  // 1st - 87th percentile
    { points: 2, min: 11, max: 74 }, // 88thth - 99th percentile
    { points: 3, min: 93, max: 93 }  // 100th percentile
]
let seshPoints = [
    { points: 1, min: 1, max: 1 },     // 1st - 52nd percentile
    { points: 2, min: 2, max: 41 },    // 53rd - 75th percentile
    { points: 3, min: 148, max: 148 }  // 76th - 100th percentile
]
let sacPoints = [
    { points: 1, min: 1, max: 1 },   // 1st - 46th percentile
    { points: 2, min: 2, max: 9 },   // 47th - 93rd percentile
    { points: 3, min: 10, max: 132 } // 94th - 100th percentile
]
let wabPoints = [
    { points: 1, min: 1, max: 1 },   // 1st - 25th percentile
    { points: 2, min: 2, max: 9 }, // 26th - 75th percentile
    { points: 3, min: 10, max: 10 } // 76th - 100th percentile
]

// DISTRIBUTION CSV LOCATIONS
let headstashDistributions = [
    { points: bbPoints, csv: "../headstash/communities/buddah-bears/bb.csv" },
    { points: budsPoints, csv: "../headstash/communities/monster-buds/buds.csv" },
    { points: cbPoints, csv: "../headstash/communities/cannabuddies/cb.csv", },
    { points: cccPoints, csv: "../headstash/communities/crypto-canna-club/ccc.csv", },
    { points: chtPoints, csv: "../headstash/communities/chronic-token/cht.csv" },
    { points: ggPoints, csv: "../headstash/communities/galacktic-gang/gg.csv" },
    { points: hlkPoints, csv: "../headstash/communities/hippie-life-krew/hlk.csv" },
    { points: rebudPoints, csv: "../headstash/communities/rebud/rebud.csv" },
    { points: seshPoints, csv: "../headstash/communities/secret-sesh/sesh.csv" },
    { points: sacPoints, csv: "../headstash/communities/stoned-ape-club/sac.csv" },
    { points: wabPoints, csv: "../headstash/communities/wake-and-bake/wab.csv" },
]

// ETPP (Estimated Token Per Point)
let etpp = [
    { points: bbPoints, tpp: 1762.237762 },
    { points: budsPoints, tpp: 1861.152142 },
    { points: cbPoints, tpp: 1595.744681 },
    { points: cccPoints, tpp: 2080.924855 },
    { points: chtPoints, tpp: 4615.384615 },
    { points: ggPoints, tpp: 1688.102894 },
    { points: hlkPoints, tpp: 2147.239264 },
    { points: rebudPoints, tpp: 1861.152142 },
    { points: seshPoints, tpp: 1992.409867 },
    { points: sacPoints, tpp: 1577.524038 },
    { points: wabPoints, tpp: 1660.079051 },
]

// step 1: determine point distribution for each communinty
// step 2: determine tokens to allocate for address based on tpp  
// step 3: check for reoccurring addresses between all communnities. if addr exists, sum together points allocated.
// step 4: if address is not eth address, we need to base64 encode the address (as it is a solana public address)
// step 5: create new 1 new csv with final tally 

function determinePointDistribution(points, amount) {
    for (let i = 0; i < points.length; i++) {
        if (amount >= points[i].min && amount <= points[i].max) {
            return points[i].points;
        }
    }
    return 0;
}

function isEthereumAddress(address) {
    return address.length === 42 && address.startsWith('0x');
}

function encodeSolanaAddress(address) {
    return Buffer.from(address, 'utf-8').toString('base64');
}

// Create an object to store the final tally
let finalTally = {};

// Async function to process the community distributions
async function processDistributions() {
    for (let distribution of headstashDistributions) {
        try {
            // Find the ETPP for the current community
            let communityETPP = etpp.find((etppItem) => JSON.stringify(etppItem.points) === JSON.stringify(distribution.points));

            // Read the CSV file for the current community
            const csvData = await readCsvFile(distribution.csv);

            // Process the CSV data
            csvData.forEach((row) => {
                // Get the address and amount from the current row
                let address = row.addr;
                let amount = parseInt(row.amount);

                // Determine the point distribution for the current row
                let points = determinePointDistribution(distribution.points, amount);

                // Calculate the token allocation for the current row
                let tokens = points * communityETPP.tpp;

                // Check if the address is an Ethereum address or a Solana public address
                if (!isEthereumAddress(address)) {
                    address = encodeSolanaAddress(address);
                }

                // Add the tokens to the final tally
                if (address in finalTally) {
                    finalTally[address] += tokens;
                } else {
                    finalTally[address] = tokens;
                }
            });
        } catch (error) {
            console.error(`Error processing distribution: ${error}`);
        }
    }

    // Create a new CSV file with the final tally
    try {
        await createFinalTallyCsv(finalTally);
        console.log('Final tally CSV file created successfully!');
    } catch (error) {
        console.error(`Error creating final tally CSV: ${error}`);
    }
}

// Function to read a CSV file
function readCsvFile(filePath) {
    return new Promise((resolve, reject) => {
        const csvData = [];

        fs.createReadStream(filePath)
            .pipe(csv())
            .on('data', (row) => {
                csvData.push(row);
            })
            .on('end', () => {
                resolve(csvData);
            })
            .on('error', (error) => {
                reject(error);
            });
    });
}

// Function to create the final tally CSV file
function createFinalTallyCsv(finalTally) {
    return new Promise((resolve, reject) => {
        let csvContent = "addr,points\n";
        Object.keys(finalTally).sort((a, b) => finalTally[b] - finalTally[a]).forEach((address) => {
            csvContent += `${address},${finalTally[address]}\n`;
        });

        fs.writeFile('../headstash/final_tally.csv', csvContent, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
}

export { processDistributions }