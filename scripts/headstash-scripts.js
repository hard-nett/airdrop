// Headstash Scripts that creates a single file from each community distribution csv.
// 1. calculate points for each community
// 2. identify and merge any address that exist in multiple community distributions 
// 3. if solana wallet, base64 encode wallet address 
import fs from 'fs';
import csv from 'csv-parser';


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