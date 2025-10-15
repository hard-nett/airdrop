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


// Convert percentileValues to Markdown table
function toMarkdownTable(data) {
    if (!data || Object.keys(data).length === 0) return 'No data';

    let rows;

    if (Array.isArray(data)) {
        rows = data;
    } else {
        // Convert { "1%": { ... } } → [ { percentile: "1%", ... } ]
        rows = Object.entries(data).map(([key, value]) => ({
            percentile: key,
            ...value
        }));
    }

    const headers = Object.keys(rows[0]);
    const separator = headers.map(() => '---');

    return [
        '| ' + headers.join(' | ') + ' |',
        '| ' + separator.join(' | ') + ' |',
        ...rows.map(row => '| ' + headers.map(h => String(row[h] ?? '')).join(' | ') + ' |')
    ].join('\n');
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // Escape special regex chars
}

export { readCsvFile, readJsonFile, readYamlFile, toMarkdownTable, escapeRegExp }

