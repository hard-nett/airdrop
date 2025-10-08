
import { readCsvFile, readYamlFile } from "./utils.js";
import readline from 'readline';
import { HEADSTASH_YAML } from './constants.js'
import fs from 'fs';
import path from 'path'
import { parse, stringify } from 'yaml'

// Helper to prompt input
const ask = (query) => {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    return new Promise((resolve) => rl.question(query, (ans) => {
        rl.close();
        resolve(ans.trim());
    }));
};

async function loadProjectAddresses(csvPath) {
    const rows = await readCsvFile(csvPath);
    // Assume CSV has headers: addr,amount
    return rows.map((r) => ({
        addr: r.addr,
        amount: r.amount
    }));
}
export const fairPercentileRanges = async (yamlFile) => {
    const distributionData = await readYamlFile(yamlFile);
    const projects = await Promise.all(
        Object.values(distributionData.projects).map(async (proj) => {
            const records = await loadProjectAddresses(proj.csv);
            const holders = records
                .map((r) => ({
                    address: r.addr,
                    amount: parseFloat(r.amount),
                }))
                .filter((h) => !isNaN(h.amount));

            holders.sort((a, b) => b.amount - a.amount); // descending

            return { ...proj, holders };
        })
    );

    console.log("✅ loaded projects:", projects.map((p) => p.name));

    // Generate 3% increments: 3%, 6%, ..., 99%
    const percentiles = [];
    for (let p = 0.01; p <= 1; p += 0.01) {
        percentiles.push(parseFloat(p.toFixed(2)));
    }

    const configResults = {};

    // Process each project
    for (const proj of projects) {
        const { holders, name } = proj;
        if (holders.length === 0) {
            console.warn(`⚠️ No valid holder data for project: ${name}`);
            continue;
        }

        const total = holders.length;
        const percentileValues = {};

        // Build data for table
        for (const p of percentiles) {
            const idx = Math.floor(p * total);
            if (idx >= total) continue;
            const rank = idx + 1;
            const { amount } = holders[idx];
            const label = `${Math.round(p * 100)}%`;
            percentileValues[label] = {
                rank,
                totalHolders: total,
                requiredAmount: amount
            };
        }

        // ✅ Print the nice table you liked
        console.log(`\n📊 ${name} - 3% percentile ranges:`);
        console.table(percentileValues);

        // Interactive cutoff configuration
        console.log(`\n🎯 Now setting point tiers for ${name}...`);

        let threePerc;
        while (!threePerc) {
            const input = await ask(`   🥇 Top __% get 3 points? (1-99): `);
            const n = parseFloat(input);
            if (isNaN(n) || !Number.isInteger(n) || n < 1 || n > 99) {
                console.log(`   ❌ Invalid. Please enter a whole number between 1 and 99.`);
                continue;
            }
            const decimalValue = n / 100;
            if (percentiles.includes(decimalValue)) {
                threePerc = decimalValue;
            } else {
                console.log(`   ❌ ${n}% is not supported.`);
            }
        }

        let twoPerc;
        while (!twoPerc) {
            const input = await ask(`   🥈 Extend 2 points up to __%? (must be > ${threePerc * 100}%): `);
            const n = parseFloat(input);
            if (isNaN(n) || !Number.isInteger(n) || n < 1 || n > 99) {
                console.log(`   ❌ Must be a whole number between 1 and 99.`);
                continue;
            }
            const decimalValue = n / 100;
            if (decimalValue <= threePerc) {
                console.log(`   ❌ Must be greater than ${threePerc * 100}.`);
                continue;
            }
            if (!percentiles.includes(decimalValue)) {
                console.log(`   ❌ ${n}% is not supported.`);
                continue;
            }
            twoPerc = decimalValue;
        }

        // Calculate number of holders in each point tier
        const threePointCutoffIdx = Math.floor(threePerc * total);
        const twoPointCutoffIdx = Math.floor(twoPerc * total);

        const numThreePointHolders = threePointCutoffIdx + 1; // +1 because 0-indexed
        const numTwoPointHolders = twoPointCutoffIdx - threePointCutoffIdx;
        const numOnePointHolders = total - twoPointCutoffIdx - 1;

        // Save configuration
        configResults[name] = {
            threePointsUpTo: { value: threePerc, holders: numThreePointHolders },
            twoPointsUpTo: { value: twoPerc, holders: numTwoPointHolders },
            onePointUpTo: {
                value: 1.0,
                holders: numOnePointHolders
            },
            totalHolders: total,
        };

        await updateHeadstashYaml(configResults, name);
        console.log(` ✅ ${name} configured: 3pts ≤ ${threePerc * 100}%, 2pts ≤ ${twoPerc * 100}%, 1pt rest\n`);
    }

    // Final result
    console.log("📋 Full configuration results:");
    console.log(configResults);
    // update yaml file with points distirbution details

    return;
};


export const updateHeadstashYaml = async (configResults, name) => {
    const doc = await readYamlFile(HEADSTASH_YAML)

    // Find the specific project by name in configResults
    const config = configResults[name];
    if (!config) {
        console.warn(` ⚠️ Project "${name}" not found in config results`);
        return;
    }

    // Find project by name in the YAML under `projects`
    const project = doc.projects?.find(p => p.name === name);
    if (project) {
        project.points = {
            threePointsUpTo: config.threePointsUpTo,
            twoPointsUpTo: config.twoPointsUpTo,
            onePointUpTo: config.onePointUpTo,
            totalHolders: config.totalHolders
        };
        console.log(` 📥 Updated ${name} points distribution in headstash.yaml`);
    } else {
        console.warn(` ⚠️ Project "${name}" not found in headstash.yaml`);
    }

    fs.writeFileSync(HEADSTASH_YAML, stringify(doc), 'utf8');
    console.log(`✅ headstash.yaml updated with new points distribution for "${name}"`);
};