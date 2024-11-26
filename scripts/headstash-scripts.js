// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import csv from 'csv-parser';
import path from 'path'

let etpp = [
    {
        csv: "../headstash/communities/carta-beta-gang/carta.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 88th percentile
            { points: 2, min: 2, max: 3 }, // 88st - 99th percentile
            { points: 3, min: 15, max: 15 }, // 100th percentile
        ],
        tpp: 1431.818182 // 0.06% 
    },
    {
        csv: "../headstash/communities/cryptowizards/cw.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 71th percentile
            { points: 2, min: 2, max: 5 }, // 72st - 96th percentile
            { points: 3, min: 6, max: 14 }, // 97th - 100th 
        ],
        tpp: 1150.684932 // 0.02%
    },
    {
        csv: "../headstash/communities/heady-pipe-society/hps.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 56th percentile
            { points: 2, min: 2, max: 5 }, // 72st - 95th percentile
            { points: 3, min: 6, max: 10 }, // 96th - 100th 
        ],
        tpp: 1852.941176 // 0.015%
    },
    {
        csv: "../headstash/communities/n8/n8.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 72nd percentile
            { points: 2, min: 2, max: 3 }, // 73rd - 98th percentile
            { points: 3, min: 4, max: 6 }, // 99th - 100th percentile
        ],
        tpp: 1547.911548 // 0.15% 
    },
    {
        csv: "../headstash/communities/special-k/special-k.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 76th percentile
            { points: 2, min: 2, max: 4 }, // 77th - 95th percentile
            { points: 3, min: 5, max: 15 }, // 96th - 100th percentile
        ],
        tpp: 1423.728814 // 0.02%
    },
    {
        csv: "../headstash/communities/buddah-bears/bb.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 87th percentile
            { points: 2, min: 2, max: 12 }, // 26th - 75th percentile
            { points: 3, min: 13, max: 790 } // 76th - 100th percentile
        ],
        tpp: 1762.237762
    },
    {
        csv: "../headstash/communities/monster-buds/buds.csv",
        points: [
            { points: 1, min: 1, max: 1 },  // 1st - 25th percentile
            { points: 2, min: 2, max: 8 },  // 26th - 75th percentile
            { points: 3, min: 9, max: 289 } // 76th - 100th percentile
        ],
        tpp: 1861.152142
    },
    {
        csv: "../headstash/communities/cannabuddies/cb.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 68th percentile
            { points: 2, min: 2, max: 3 }, // 69th - 93rd percentile
            { points: 3, min: 4, max: 9 } // 94th - 100th percentile
        ],
        tpp: 1595.744681
    },
    {
        csv: "../headstash/communities/crypto-canna-club/ccc.csv",
        points: [
            { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
            { points: 2, min: 2, max: 6 }, // 66th - 95th percentile
            { points: 3, min: 7, max: 300 } // 96th - 100th percentile
        ],
        tpp: 2080.924855
    },
    {
        csv: "../headstash/communities/chronic-token/cht.csv",
        points: [
            { points: 1, min: 2957.53, max: 29907.26 }, // 15th - 60th percentile
            { points: 2, min: 29982.06, max: 144068.86 }, // 61stth - 83rd percentile
            { points: 3, min: 146172.26, max: 1006878.94 }, // 84th - 95thpercentile
            { points: 4, min: 1016322.14, max: 52230931.14 } // 96th - 100th percentile
        ],
        tpp: 4615.384615
    },
    {
        csv: "../headstash/communities/galacktic-gang/gg.csv", points: [
            { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
            { points: 2, min: 2, max: 8 }, // 66th - 92th percentile
            { points: 3, min: 9, max: 66 } // 93rd - 100th percentile
        ], tpp: 1688.102894
    },
    {
        csv: "../headstash/communities/hippie-life-krew/hlk.csv", points: [
            { points: 1, min: 1, max: 9 },    // 1st - 89th percentile
            { points: 2, min: 10, max: 45 },  // 90th - 99th percentile
            { points: 3, min: 116, max: 116 } // 100th percentile
        ], tpp: 2147.239264
    },
    {
        csv: "../headstash/communities/rebud/rebud.csv",
        points: [
            { points: 1, min: 1, max: 10 },  // 1st - 87th percentile
            { points: 2, min: 11, max: 74 }, // 88thth - 99th percentile
            { points: 3, min: 93, max: 93 }  // 100th percentile
        ],
        tpp: 1861.152142
    },
    {
        csv: "../headstash/communities/secret-sesh/sesh.csv", points: [
            { points: 1, min: 1, max: 1 },     // 1st - 52nd percentile
            { points: 2, min: 2, max: 41 },    // 53rd - 75th percentile
            { points: 3, min: 148, max: 148 }  // 76th - 100th percentile
        ], tpp: 1992.409867
    },
    {
        csv: "../headstash/communities/stoned-ape-club/sac.csv", points: [
            { points: 1, min: 1, max: 1 },   // 1st - 46th percentile
            { points: 2, min: 2, max: 9 },   // 47th - 93rd percentile
            { points: 3, min: 10, max: 132 } // 94th - 100th percentile
        ], tpp: 1577.524038
    },
    {
        csv: "../headstash/communities/wake-and-bake/wab.csv", points: [
            { points: 1, min: 1, max: 1 },   // 1st - 25th percentile
            { points: 2, min: 2, max: 9 }, // 26th - 75th percentile
            { points: 3, min: 10, max: 10 } // 76th - 100th percentile
        ], tpp: 1660.079051
    },
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

async function processHeadstashDistributions() {
    let addressCommunities = {};
    let communities = [];

    for (let distribution of etpp) {
        try {
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
                let tokens = points * distribution.tpp;

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

                // Add the community to the address's communities
                if (!addressCommunities[address]) {
                    addressCommunities[address] = {};
                }
                if (!addressCommunities[address][distribution.csv]) {
                    addressCommunities[address][distribution.csv] = 0;
                }
                addressCommunities[address][distribution.csv] += points;

                // Add the community to the list of communities
                if (!communities.includes(distribution.csv)) {
                    communities.push(distribution.csv);
                }
            });
        } catch (error) {
            console.error(`Error processing distribution: ${error}`);
        }
    }

    // Create a new CSV file with the final tally
    try {
        await createFinalTallyCsv(finalTally, addressCommunities, communities);
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
function createFinalTallyCsv(finalTally, addressCommunities, communities) {
    return new Promise((resolve, reject) => {
        let csvContent = "addr,points";
        for (let community of communities) {
            csvContent += `,${path.basename(community)}`;
        }
        csvContent += "\n";

        Object.keys(finalTally).sort((a, b) => finalTally[b] - finalTally[a]).forEach((address) => {
            let row = `${address},${finalTally[address]}`;
            for (let community of communities) {
                if (addressCommunities[address] && addressCommunities[address][community]) {
                    row += `,${addressCommunities[address][community]}`;
                } else {
                    row += ",0";
                }
            }
            csvContent += row + "\n";
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
export { processHeadstashDistributions }