// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import csv from 'csv-parser';

// DISTRIBUTION CSV LOCATIONS
let headstashDistributions = [
    "../headstash/communities/buddah-bears/bb.csv",
    "../headstash/communities/cannabuddies/cb.csv",
    "../headstash/communities/chronic-token/cht.csv",
    "../headstash/communities/crypto-canna-club/ccc.csv",
    "../headstash/communities/galacktic-gang/gg.csv",
    "../headstash/communities/hippie-life-krew/hlk.csv",
    "../headstash/communities/monster-buds/the-buds.csv",
    "../headstash/communities/rebud/rebud.csv",
    "../headstash/communities/secret-sesh/sesh.csv",
    "../headstash/communities/stoned-ape-club/sac.csv",
    "../headstash/communities/wake-and-bake/wab.csv",
]

// PERCENTILE RANGE POINTS
let bbPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 87th percentile
    { points: 2, min: 2, max: 12 }, // 26th - 75th percentile
    { points: 3, min: 13, max: 790 } // 76th - 100th percentile
]
let cccPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
    { points: 2, min: 2, max: 6 }, // 66th - 95th percentile
    { points: 3, min: 7, max: 300 } // 96th - 100th percentile
]
let chtPoints = [
    { points: 1, min: 2957.53, max: 29907.26 }, // 15th - 60th percentile
    { points: 2, min: 29982.06, max: 144068.86 }, // 61stth - 83rd percentile
    { points: 3, min: 146172.26, max: 1006878.94 }, // 84th - 95thpercentile
    { points: 4, min: 1016322.14, max: 52230931.14 } // 96th - 100th percentile
]
let cbPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 68th percentile
    { points: 2, min: 2, max: 3 }, // 69th - 93rd percentile
    { points: 3, min: 4, max: 9 } // 94th - 100th percentile
]
let ggPoints = [
    { points: 1, min: 1, max: 1 }, // 1st - 65th  percentile
    { points: 2, min: 2, max: 8 }, // 66th - 92th percentile
    { points: 3, min: 9, max: 66 } // 93rd - 100th percentile
]
let hlkPoints = [
    { points: 1, min: 1, max: 9 },    // 1st - 89th percentile
    { points: 2, min: 10, max: 45 },  // 90th - 99th percentile
    { points: 3, min: 116, max: 116 } // 100th percentile
]
let mosterBudsPoints = [
    { points: 1, min: 1, max: 1 },  // 1st - 25th percentile
    { points: 2, min: 2, max: 8 },  // 26th - 75th percentile
    { points: 3, min: 9, max: 289 } // 76th - 100th percentile
]
let rebudPoints = [
    { points: 1, min: 1, max: 10 },  // 1st - 87th percentile
    { points: 2, min: 11, max: 74 }, // 88thth - 99th percentile
    { points: 3, min: 93, max: 93 }  // 100th percentile
]
let secretSeshPoints = [
    { points: 1, min: 1, max: 1 },     // 1st - 52nd percentile
    { points: 2, min: 2, max: 41 },    // 53rd - 75th percentile
    { points: 3, min: 148, max: 148 }  // 76th - 100th percentile
]
let sacPoints = [
    { points: 1, min: 1, max: 1 },   // 1st - 46th percentile
    { points: 2, min: 2, max: 9 },   // 47th - 93rd percentile
    { points: 3, min: 10, max: 132 } // 94th - 100th percentile
]
let wabPoints = [
    { points: 1, min: 1, max: 1 },   // 1st - 25th percentile
    { points: 2, min: 2, max: 9 }, // 26th - 75th percentile
    { points: 3, min: 10, max: 10 } // 76th - 100th percentile
]