// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import path from 'path'
import { readCsvFile } from './utils.js';

const HEADSTASH_DISTRIBUTION_DATA = [
    {
        name: "buddah-bears",
        numOfHolders: 2453,
        percTotalSupply: 1.5,
        csv: "../headstash/communities/buddah-bears/buddah-bears.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 1461 }, // 1st - 59th
            { points: 2, min: 2, max: 6, holders: 769 }, // 60th - 90th
            { points: 3, min: 7, max: 790, holders: 223 } // 91st - 100th
        ],
        tpp: 1762.237762
    },
    {
        name: "cannabuddies",
        numOfHolders: 238,
        percTotalSupply: 0.125,
        csv: "../headstash/communities/cannabuddies/cannabuddies.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 162 }, // 1st - 59th
            { points: 2, min: 2, max: 3, holders: 61 }, // 60th - 90th
            { points: 3, min: 4, max: 9, holders: 15 }  // 91st - 100th
        ],
        tpp: 1595.744681
    },
    {
        name: "carta-beta-gang",
        numOfHolders: 157,
        percTotalSupply: 0.06,
        csv: "../headstash/communities/carta-beta-gang/carta-beta-gang.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 139 }, // 1st - 88th
            { points: 2, min: 2, max: 3, holders: 17 },  // 89th - 99th 
            { points: 3, min: 15, max: 15, holders: 1 }, // 100th
        ],
        tpp: 1431.818182 // 0.06% 
    },
    {
        name: "chronic-token",
        numOfHolders: 1256,
        percTotalSupply: 2.0,
        csv: "../headstash/communities/chronic-token/chronic-token.csv",
        points: [
            { points: 1, min: 2949.07, max: 29907.26, holders: 577 },    // 15th - 60th
            { points: 2, min: 29907.27, max: 126425.37, holders: 288 },  // 61st - 83rd
            { points: 3, min: 126425.38, max: 631620.69, holders: 151 }, // 84th - 95th
            { points: 4, min: 631620.7, max: 52230931.14, holders: 63 } // 96th - 100th 
        ],
        tpp: 4615.384615
    },
    {
        name: "crypto-canna-club",
        numOfHolders: 4405,
        percTotalSupply: 3.0,
        csv: "../headstash/communities/crypto-canna-club/crypto-canna-club.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 2948 }, // 1st - 65th
            { points: 2, min: 2, max: 6, holders: 1264 }, // 66th - 95th
            { points: 3, min: 7, max: 300, holders: 193 } // 96th - 100th
        ],
        tpp: 2080.924855
    },
    {
        name: "cryptowizards",
        numOfHolders: 55,
        percTotalSupply: 0.02,
        csv: "../headstash/communities/cryptowizards/cryptowizards.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 39 }, // 1st - 70th
            { points: 2, min: 2, max: 4, holders: 14 }, // 71st - 95th
            { points: 3, min: 5, max: 14, holders: 2 }, // 96th - 100th 
        ],
        tpp: 1150.684932 // 0.02%
    },
    {
        name: "galacktic-gang",
        numOfHolders: 2566,
        percTotalSupply: 1.5,
        csv: "../headstash/communities/galacktic-gang/galacktic-gang.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 1620 }, // 1st - 63rd
            { points: 2, min: 2, max: 4, holders: 726 }, // 64th - 95th
            { points: 3, min: 5, max: 66, holders: 220 } // 96th - 100th
        ],
        tpp: 1688.102894
    },
    {
        name: "heady-pipe-society",
        numOfHolders: 342,
        percTotalSupply: 0.25,
        csv: "../headstash/communities/heady-pipe-society/heady-pipe-society.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 13 }, // 1st - 56th 
            { points: 2, min: 2, max: 5, holders: 9 }, // 72st - 95th
            { points: 3, min: 6, max: 10, holders: 1 }, // 96th - 100th 
        ],
        tpp: 1852.941176 // 0.015%
    },
    {
        name: "hippie-life-krew",
        numOfHolders: 342,
        percTotalSupply: 0.25,
        csv: "../headstash/communities/hippie-life-krew/hippie-life-krew.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 309 },   // 1st - 37th 
            { points: 2, min: 2, max: 22, holders: 32 },  // 38th - 99th 
            { points: 3, min: 23, max: 116, holders: 1 } // 100th
        ],
        tpp: 2147.239264
    },
    {
        name: "monster-buds",
        numOfHolders: 3385,
        percTotalSupply: 1.5,
        csv: "../headstash/communities/monster-buds/monster-buds.csv",
        points: [
            { points: 1, min: 1, max: 1, holders: 1684 },    // 1st - 49th
            { points: 2, min: 2, max: 10, holders: 1473 },   // 26th - 93rd
            { points: 3, min: 11, max: 289, holders: 228 }  // 94th - 100th 
        ],
        tpp: 1861.152142
    },
    {
        name: "rebud",
        csv: "../headstash/communities/rebud/rebud.csv",
        numOfHolders: 585,
        percTotalSupply: 0.35,
        tpp: 1861.152142,
        points: [
            { points: 1, min: 1, max: 10, holders: 513 },  // 1st - 87th percentile
            { points: 2, min: 11, max: 41, holders: 71 }, // 88th - 99th percentile
            { points: 3, min: 42, max: 93, holders: 1 }  // 100th percentile
        ],
    },
    {
        name: "secret-sesh",
        csv: "../headstash/communities/secret-sesh/secret-sesh.csv",
        numOfHolders: 780,
        percTotalSupply: 0.25,
        points: [
            { points: 1, min: 1, max: 1, holders: 275 },
            { points: 2, min: 2, max: 4, holders: 200 },
            { points: 3, min: 5, max: 148, holders: 52 }
        ],
        tpp: 1992.409867
    },
    {
        name: "shurlok",
        csv: "../headstash/communities/shurlok/shurlok.csv",
        numOfHolders: 33,
        percTotalSupply: 0.025,
        tpp: 1660.079051,
        points: [
            { points: 1, min: 1, max: 1, holders: 23 },   // 1st - 25th percentile
            { points: 2, min: 2, max: 5, holders: 6 }, // 26th - 75th percentile
            { points: 3, min: 6, max: 89, holders: 4 } // 76th - 100th percentile
        ],
    },
    {
        name: "special-k",
        csv: "../headstash/communities/special-k/special-k.csv",
        numOfHolders: 46,
        percTotalSupply: 0.02,
        tpp: 1423.728814, // 0.02%
        points: [
            { points: 1, min: 1, max: 1, holders: 35 }, // 1st - 76th percentile
            { points: 2, min: 2, max: 4, holders: 9 }, // 77th - 95th percentile
            { points: 3, min: 5, max: 15, holders: 2 }, // 96th - 100th percentile
        ],
    },
    {
        name: "stoned-ape-club",
        csv: "../headstash/communities/stoned-ape-club/stoned-ape-club.csv",
        numOfHolders: 2059,
        percTotalSupply: 1.25,
        tpp: 1577.524038,
        points: [
            { points: 1, min: 1, max: 1, holders: 965 },   // 1st - 46th 
            { points: 2, min: 2, max: 9, holders: 968 },   // 47th - 93rd 
            { points: 3, min: 10, max: 132, holders: 126 } // 94th - 100th 
        ],
    },
    {
        name: "wake-and-bake",
        csv: "../headstash/communities/wake-and-bake/wake-and-bake.csv",
        numOfHolders: 154,
        percTotalSupply: 0.1,
        tpp: 1660.079051,
        points: [
            { points: 1, min: 1, max: 1, holders: 88 },   // 1st - 25th  
            { points: 2, min: 2, max: 9, holders: 33 }, // 26th - 75th 
            { points: 3, min: 10, max: 10, holders: 33 } // 76th - 100th  
        ],
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

    for (let distribution of HEADSTASH_DISTRIBUTION_DATA) {
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



// Function to create the final tally CSV file
function createFinalTallyCsv(finalTally, addressCommunities, communities) {
    return new Promise(async (resolve, reject) => {
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

        fs.writeFile('../headstash/scripts-data/final_tally.csv', csvContent, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });

        try {
            await createCommunityPointsSummaryCsv(addressCommunities, communities);
            console.log('Community points summary CSV file created successfully!');
        } catch (error) {
            console.error(`Error creating community points summary CSV: ${error}`);
        }
    });
}

// Function to create the community points summary CSV file
function createCommunityPointsSummaryCsv(addressCommunities, communities) {
    return new Promise((resolve, reject) => {
        let communityPoints = {};

        // Calculate the sum of points for each community
        communities.forEach((community) => {
            communityPoints[community] = { points: {}, addrCount: 0 };
            Object.keys(addressCommunities).forEach((address) => {
                if (addressCommunities[address][community]) {
                    communityPoints[community].addrCount++;
                    const points = addressCommunities[address][community];
                    if (communityPoints[community].points[points]) {
                        communityPoints[community].points[points]++;
                    } else {
                        communityPoints[community].points[points] = 1;
                    }
                }
            });
        });

        // Create the CSV content
        let csvContent = "community,addrCount,points,count\n";
        communities.forEach((community) => {
            Object.keys(communityPoints[community].points).forEach((points) => {
                csvContent += `${path.basename(community)},${communityPoints[community].addrCount},${points},${communityPoints[community].points[points]}\n`;
            });
        });

        // Write the CSV file
        fs.writeFile('../headstash/scripts-data/community_points_summary.csv', csvContent, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
}

export { processHeadstashDistributions, HEADSTASH_DISTRIBUTION_DATA }