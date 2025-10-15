// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import path from 'path'
import { readCsvFile, readYamlFile } from './utils.js';
import { HEADSTASH_YAML, HEADSTASH_FINAL_TALLY } from './constants.js'


// step 1: determine point distribution for each communinty
// step 2: determine tokens to allocate for address based on tpp  
// step 3: check for reoccurring addresses between all communnities. if addr exists, sum together points allocated.
// step 4: if address is not eth address, we need to base64 encode the address (as it is a solana public address)
// step 5: create new 1 new csv with final tally 

function determinePointDistribution(pointsConfig, percentile) {
    // percentile is a decimal: 0.0 to 1.0
    if (percentile <= pointsConfig.threePointsUpTo.value) {
        return 3;
    } else if (percentile <= pointsConfig.twoPointsUpTo.value) {
        return 2;
    } else if (percentile <= pointsConfig.onePointUpTo.value) {
        return 1;
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

async function processHeadstashDistributions(yamlFile) {
    let addressCommunities = {};
    let communities = [];

    const data = await readYamlFile(yamlFile);
    // create percentile ranges
    // await fairPercentileRanges(data);

    for (let distribution of data.projects) {
        try {
            // Read the CSV file for the current community
            const csvData = await readCsvFile(distribution.csv);

            // Process the CSV data
            csvData.forEach((row) => {
                // Get the address and amount from the current row
                let address = row.addr;
                console.log(row.amount)
                let amount = parseInt(row.amount);
                console.log(`amount ${amount}`, amount)
                // Determine the point distribution for the current row
                let points = determinePointDistribution(distribution.points, amount);
                console.log(`points ${points}`, points)
                // Calculate the token allocation for the current row
                let tokens = points * distribution.tpp;
                console.log(`tokens ${tokens}`, tokens)
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

        fs.writeFile(HEADSTASH_FINAL_TALLY, csvContent, (err) => {
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

export { processHeadstashDistributions, }