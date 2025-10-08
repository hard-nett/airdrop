
// inputs
const TOTAL_SUPPLY = 420000000;
const GAIA_PERC_SUPPLY = 0.061152;
const BCNA_PERC_SUPPLY = 0.01911;
const NETWORK_GENESIS_FILE = "../data/genesis.json"
const LIVE_NETWORK_EXPORT_FILE = "../data/export.json"
const GENESIS_DISTRIBUTION_FILE = '../genesis/scripts-data/final-output.csv';
const PATCHED_DISTRIBUTION_FILE = "../genesis/scripts-data/patched-distribution.csv"
const INACTIVE_ACCOUNT_FILE = "../genesis/scripts-data/accounts-inactive.json"
const ACTIVE_ACCOUNTS_FILE = "../genesis/scripts-data/accounts-active.json"
const TOKEN_DIFF_OUTPUT = "../genesis/scripts-data/token-differences.csv"
const SUMMARY_OUTPUT = "../genesis/scripts-data/summary.json"
const POINTS_SUMMARY_FILE = '../genesis/scripts-data/points-distribution.csv';
const TOTAL_POINTS_FILE = '../genesis/scripts-data/total-points.csv';
const SAC_JSON_PATH = '../headstash/communities/sac.json';
const SAC_INPUT_CSV_PATH = '../headstash/communities/stoned-ape-club/sac-w-tokens.csv';
const SAC_OUTPUT_CSV_PATH = '../headstash/communities/stoned-ape-club/sac-w-tokens-encoded.csv';
const SCAVENGER_HUNT_FILE = "../genesis/scavenger_hunt.csv";
const TERPOG_FILE = "../genesis/terp_og.csv";
const BCNA_DELEGATORS = "../genesis/bcna_delegators.csv";
const GAIA_DELEGATORS = "../genesis/gaia.csv";


HEADSTASH_YAML = "./headstash.yaml";


export {
    TOTAL_SUPPLY,
    NETWORK_GENESIS_FILE,
    LIVE_NETWORK_EXPORT_FILE,
    SCAVENGER_HUNT_FILE,
    TERPOG_FILE,
    SAC_JSON_PATH,
    SAC_INPUT_CSV_PATH,
    SAC_OUTPUT_CSV_PATH,
    BCNA_DELEGATORS,
    GAIA_DELEGATORS,
    HEADSTASH_YAML,
    ACTIVE_ACCOUNTS_FILE,
    TOKEN_DIFF_OUTPUT,
    SUMMARY_OUTPUT,
    PATCHED_DISTRIBUTION_FILE,
    POINTS_SUMMARY_FILE,
    INACTIVE_ACCOUNT_FILE,
    GENESIS_DISTRIBUTION_FILE,
    BCNA_PERC_SUPPLY,
    GAIA_PERC_SUPPLY,
    TOTAL_POINTS_FILE,
};