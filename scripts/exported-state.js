import fs from 'fs';
import csv from 'csv-parser';
// 1. find & filter all accounts that:
// a. exist in final_output.csv
// b. has not performed any actions (sequence is 0)
// c. have performed more than one action sequence is > 0 


const networkExport = "../data/export.json"
const genesisDistribution = "../genesis/scripts-data/final_output.csv"


function processExportedState() {
    // Read the JSON file
    fs.readFile(networkExport, (err, data) => {
        if (err) {
            console.error(err);
            return;
        }

        // Parse the JSON data
        const jsonData = JSON.parse(data);
        const accounts = jsonData.app_state.auth.accounts;

        // Read the CSV file
        const genesisAccounts = [];
        fs.createReadStream(genesisDistribution)
            .pipe(csv())
            .on('data', (row) => {
                genesisAccounts.push(row);
            })
            .on('end', () => {
                const matchingAccounts = accounts.filter((account) => {
                    return genesisAccounts.some((genesisAccount) => genesisAccount.address === account.address);
                });
                const updatedZeroSequenceAccounts = [];
                const updatedGreaterZeroSequenceAccounts = [];
                matchingAccounts.forEach((account) => {
                    if (account.base_vesting_account) {
                        // Separate accounts by sequence
                        const accountInfo = {
                            account_number: account.base_vesting_account.base_account.account_number,
                            address: account.base_vesting_account.base_account.address,
                            sequence: account.base_vesting_account.base_account.sequence,
                            original_vesting_amount: account.base_vesting_account.original_vesting[0].amount
                        };

                        if (account.base_vesting_account.base_account.sequence === '0') {
                            updatedZeroSequenceAccounts.push(accountInfo);
                        } else {
                            updatedGreaterZeroSequenceAccounts.push(accountInfo);
                        }
                    }
                });
                updatedGreaterZeroSequenceAccounts.sort((a, b) => parseInt(b.sequence) - parseInt(a.sequence));
                const updatedZeroSequenceAccountsJson = { app_state: { auth: { accounts: updatedZeroSequenceAccounts } } };
                fs.writeFileSync('../genesis/scripts-data/updated_zero_sequence_accounts.json', JSON.stringify(updatedZeroSequenceAccountsJson, null, 2));
                const updatedGreaterZeroSequenceAccountsJson = { app_state: { auth: { accounts: updatedGreaterZeroSequenceAccounts } } };
                fs.writeFileSync('../genesis/scripts-data/updated_greater_zero_sequence_accounts.json', JSON.stringify(updatedGreaterZeroSequenceAccountsJson, null, 2));
            });
    });
}
// const newPoints =
//     [
//         { p: 5, expected: 5669.008569, actual: 5669.008569, new: 6941.7584 },
//         { p: 6, expected: 5711.387496, actual: 5784.610414, new: 8330.11008 },
//         { p: 7, expected: 10991.211595, actual: 5553.406723, new: 13497.424297 },
//         { p: 8, expected: 8330.11008, actual: 5669.008569, new: 13497.424297 },
//         { p: 9, expected: 16313.414625, actual: 5784.610414, new: 15425.627768 },
//     ]

export { processExportedState }