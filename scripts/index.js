import fs from 'fs';
import csv from 'csv-parser';

// Read the input CSV file
fs.readFile('../eth/raw-holder.csv', 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }

    const processData = (data) => {
        const namesValues = [];
        const duplicatedNames = {};

        // Parse the CSV data
        data.split('\n').forEach((row) => {
            const [name, value] = row.split(',');
            namesValues.push({ name, value: value });
        });

        // Group duplicates by name
        namesValues.forEach((entry) => {
            if (entry.name.startsWith('0x')) { 
                if (duplicatedNames[entry.name]) {
                    duplicatedNames[entry.name] = (parseFloat(duplicatedNames[entry.name]) + parseFloat(entry.value)).toFixed(6);
                } else {
                    duplicatedNames[entry.name] = parseFloat(entry.value).toFixed(6);
                }
            }
        });

        // Write the result to a new CSV file
        const outputData = Object.keys(duplicatedNames).map((name) => `${name},${duplicatedNames[name]}`).join('\n');

        fs.writeFile('../eth/final-headstash.csv', outputData, 'utf8', (err) => {
            if (err) {
                console.error(err);
            } else {
                console.log('Output written to ../eth/final-headstash.csv');
            }
        });
    };

    processData(data);
});