
// inputs
// total tokens in headstash begin distributed
const BASE_ALLOCATION = 67000000;
// total supply of token
const TOTAL_SUPPLY = 420000000;

// pecentrages of genesis airdrop to gaia & bcna holders
const GAIA_PERC_SUPPLY = 0.061152;
const BCNA_PERC_SUPPLY = 0.01911;

const ETH_RPC_URL = "https://mainnet.infura.io/v3/YOUR_KEY";
// YAML files
const HEADSTASH_YAML = "../headstash.yaml";
const GENESIS_YAML_FILE = "../headstash/scripts-data/final_tally.csv";

// Exported files
const NETWORK_GENESIS_FILE = "../data/genesis.json"
const LIVE_NETWORK_EXPORT_FILE = "../data/export.json"

// Genesis Relevant Files
const GENESIS_DISTRIBUTION_FILE = '../genesis/scripts-data/final-output.csv';
const PATCHED_DISTRIBUTION_FILE = "../genesis/scripts-data/patched-distribution.csv"
const INACTIVE_ACCOUNT_FILE = "../genesis/scripts-data/accounts-inactive.json"
const ACTIVE_ACCOUNTS_FILE = "../genesis/scripts-data/accounts-active.json"
const TOKEN_DIFF_OUTPUT = "../genesis/scripts-data/token-differences.csv"
const SUMMARY_OUTPUT = "../genesis/scripts-data/summary.json"
const POINTS_SUMMARY_FILE = '../genesis/scripts-data/points-distribution.csv';
const TOTAL_POINTS_FILE = '../genesis/scripts-data/total-points.csv';
// Headstash Relevant Files
const SAC_JSON_PATH = '../headstash/communities/stoned-ape-club/sac.json';
const SAC_ENCODED_FILE = '../headstash/communities/stoned-ape-club/stoned-ape-club.csv';
const SCAVENGER_HUNT_FILE = "../genesis/scavenger_hunt.csv";
const TERPOG_FILE = "../genesis/terp_og.csv";
const BCNA_DELEGATORS = "../genesis/bcna_delegators.csv";
const GAIA_DELEGATORS = "../genesis/gaia.csv";
const HEADSTASH_FINAL_TALLY = "../headstash/scripts-data/final_tally.csv";
const SINSEMILLA_JSON_FILE = "../zk-crates/data/genesis_sinsemilla.json";
const OVERVIEW_README = "../README.md";

export {
    TOTAL_SUPPLY,
    GENESIS_YAML_FILE,
    NETWORK_GENESIS_FILE,
    LIVE_NETWORK_EXPORT_FILE,
    SCAVENGER_HUNT_FILE,
    TERPOG_FILE,
    SAC_JSON_PATH,
    SAC_ENCODED_FILE,
    BCNA_DELEGATORS,
    GAIA_DELEGATORS,
    HEADSTASH_YAML,
    HEADSTASH_FINAL_TALLY,
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
    BASE_ALLOCATION,
    SINSEMILLA_JSON_FILE,
    OVERVIEW_README,
    ETH_RPC_URL,
};