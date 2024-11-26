import fs from 'fs';
import csv from 'csv-parser';

const processSacNFTdata = async (data) => {
    const stringCounts = {};

    // Parse the JSON data
    const jsonData = JSON.parse(data);

    // Count the occurrences of each string
    jsonData.forEach((string) => {
        if (stringCounts[string]) {
            stringCounts[string]++;
        } else {
            stringCounts[string] = 1;
        }
    });

    // Sort the string counts by value in descending order
    const sortedStringCounts = Object.entries(stringCounts).sort((a, b) => b[1] - a[1]);

    // Create the output data string
    const outputData = "String,Count\n" + sortedStringCounts.map(([string, count]) => `${string},${count}`).join('\n') + '\n';

    // Write the result to a new CSV file
    fs.writeFile('../headstash/communities/sac.csv', outputData, 'utf8', (err) => {
        if (err) {
            console.error(err);
        } else {
            console.log('Output written to../headstash/communities/sac.csv');
        }
    });
};

const encodeAddrs = async (inputFile, outputFile) => {
    const inputStream = fs.createReadStream(inputFile);
    const outputStream = fs.createWriteStream(outputFile);

    inputStream
        .pipe(csv({ mapHeaders: ({ header }) => header.trim() }))
        .on('data', (row) => {
            const addr = row.Addr;
            const encodedAddr = Buffer.from(addr).toString('base64');
            outputStream.write(`${encodedAddr},${row.Amount},${row.Points},${row.Coins}\n`);
        })
        .on('end', () => {
            console.log('CSV file has been processed and written to output.csv');
        });
};


export { processSacNFTdata, encodeAddrs }