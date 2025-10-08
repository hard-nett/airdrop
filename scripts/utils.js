import fs from 'fs';
import csv from 'csv-parser';
import { parse, stringify } from 'yaml'

// Read Yaml file, parses into JSON object
const readYamlFile = async (filename) => {
    // Read existing YAML file
    const fileContent = fs.readFileSync(filename, 'utf8');
    return parse(fileContent);
};


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

// Read CSV file
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
export { readCsvFile, readJsonFile, readYamlFile }

