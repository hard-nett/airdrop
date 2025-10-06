import fs from 'fs';
import csv from 'csv-parser';

// Read JSON files
const readJsonFile = async (filename) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filename, 'utf8', (err, data) => {
            if (err) {
                reject(err);
            } else {
                resolve(JSON.parse(data));
            }
        });
    });
};

// Function to read a CSV file
function readCsvFile(filePath) {
    return new Promise((resolve, reject) => {
        const csvData = [];

        fs.createReadStream(filePath)
            .pipe(csv())
            .on('data', (row) => { csvData.push(row) })
            .on('end', () => { resolve(csvData) })
            .on('error', (error) => { reject(error) });
    });
}

export { readCsvFile, readJsonFile }

