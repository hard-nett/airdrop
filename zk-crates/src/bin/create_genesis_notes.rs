use serde::Serialize;
use serde_json::{self, Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};
use zk_crates::constants::fixed_bases::FIXED_AMOUNTS;

// The full note template (private fields are placeholders)
#[derive(Serialize, Debug, Clone)]
struct NoteTemplate {
    d: String,             // diversifier
    pk_d: String,          // diversified transmission key (ivk * G + d)
    v: String,             // amount (private)
    p: String,             // rho (nullifier input)
    ψ: String,             // psi (randomness for note commitment)
    rcm: String,           // commitment randomness
    addr_eligible: String, // original eligible address (private)
    nf_rand: String,       // randomness for nullifier derivation
}

impl From<NoteTemplate> for Value {
    fn from(nt: NoteTemplate) -> Self {
        json!({
            "d": nt.d,
            "pk_d": nt.pk_d,
            "v": nt.v,
            "p": nt.p,
            "ψ": nt.ψ,
            "rcm": nt.rcm,
            "addr_eligible": nt.addr_eligible,
            "nf_rand": nt.nf_rand
        })
    }
}

fn get_cli_args() -> Result<(String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input-file> <address>", args[0]);
        std::process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone()))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let denominations: Vec<u64> = FIXED_AMOUNTS.to_vec();

    let (input_path, addr_target) = get_cli_args()?;
    let input_data: Value = serde_json::from_str(&fs::read_to_string(&input_path)?)?;

    // generates default note using posiedon hashing algo & Fixed-Denomination Notes.
    // loads all balances, and creates genesis Fixed-Denomination Notes
    // 1_000_000_000,100_000_000,10_000_000,1_000_000, ..

    let mut address_notes = serde_json::Map::new();

    if let Value::Object(map) = &input_data {
        if let Some(holdings) = map.get(&addr_target) {
            if let Value::Array(holding_array) = holdings {
                // Step 1: Sum total balance per token
                let mut token_balances: HashMap<String, u64> = HashMap::new();
                for holding in holding_array.iter() {
                    if let Some(name) = holding["name"].as_str() {
                        let amount_str = holding["amount"].as_str().unwrap_or("0");
                        let amount: u64 = amount_str.parse().unwrap_or(0);
                        *token_balances.entry(name.to_string()).or_insert(0) += amount;
                    }
                }

                // Step 2: For each token, decompose balance into fixed denominations
                for (token_name, mut total_balance) in token_balances {
                    let mut generated_notes = Vec::new();

                    for &denom in &denominations {
                        while denom <= total_balance {
                            generated_notes.push(json!({
                                "d": "0x{diversifier}",
                                "pk_d": "0x{pk_d}",
                                "v": denom.to_string(),
                                "p": "0x{rho}",
                                "ψ": "0x{psi}",
                                "rcm": "0x{rcm}",
                                "addr_eligible": &addr_target,
                                "nf_rand": "0x{p}"
                            }));
                            total_balance -= denom;
                        }
                    }

                    // Safety check: ensure full decomposition
                    if total_balance > 0 {
                        eprintln!(
                            "⚠️ Unable to fully decompose {} {} ({} units left)",
                            total_balance, token_name, total_balance
                        );
                        std::process::exit(1);
                    }

                    address_notes.insert(token_name, Value::Array(generated_notes));
                }
            } else {
                eprintln!(
                    "Error: Address '{}' does not have holdings array.",
                    addr_target
                );
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: Address '{}' not found in input data.", addr_target);
            std::process::exit(1);
        }
    } else {
        eprintln!("Error: Input JSON must be a JSON object (map of addresses).");
        std::process::exit(1);
    }

    // Create output file: ./data/<address>_notes.json
    let output_dir = Path::new("./data/notes");
    let safe_addr: String = addr_target
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let output_path = output_dir.join(format!("{}.json", safe_addr));

    fs::create_dir_all(output_dir)?;
    fs::write(&output_path, serde_json::to_string_pretty(&address_notes)?)?;

    eprintln!("✅ Default Genesis Notes generated for {}", addr_target);
    eprintln!("📁 Written to: {}", output_path.display());

    Ok(())
}

// TODO:
// - tooling for generating values to be used in notes

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_note_accuracy() -> Result<(), Box<dyn std::error::Error>> {
        // Load original allocations
        let input_data: Value =
            serde_json::from_str(&fs::read_to_string("./data/genesis_sinsemilla.json")?)?;

        // Load generated notes for the zero address
        let notes_path = "./data/notes/0x0000000000000000000000000000000000000000.json";
        let calculated_notes: Value = serde_json::from_str(&fs::read_to_string(notes_path)?)?;

        // Extract original holdings
        let mut original_balances: HashMap<String, u64> = HashMap::new();

        if let Value::Object(map) = &input_data {
            if let Some(holdings) = map.get("0x0000000000000000000000000000000000000000") {
                if let Value::Array(holding_array) = holdings {
                    for holding in holding_array {
                        if let Some(name) = holding["name"].as_str() {
                            let amount_str = holding["amount"].as_str().unwrap_or("0");
                            let amount: u64 = amount_str.parse().unwrap_or(0);
                            *original_balances.entry(name.to_string()).or_insert(0) += amount;
                        }
                    }
                }
            }
        }

        // Extract and sum note values from generated notes
        let mut notes_sum: HashMap<String, u64> = HashMap::new();

        if let Value::Object(note_map) = &calculated_notes {
            for (token_name, notes) in note_map {
                if let Value::Array(note_array) = notes {
                    for note in note_array {
                        if let Some(v_str) = note["v"].as_str() {
                            let v: u64 = v_str.parse().unwrap_or(0);
                            *notes_sum.entry(token_name.clone()).or_insert(0) += v;
                        }
                    }
                }
            }
        }

        // Compare: original vs summed note values
        for (token, original_amount) in &original_balances {
            let note_total = notes_sum.get(token).copied().unwrap_or(0);
            assert_eq!(
                original_amount, &note_total,
                "Token {}: allocation ({}) does not match total notes ({})",
                token, original_amount, note_total
            );
        }

        // Also check for extra tokens in notes not in original
        for (token, _) in &notes_sum {
            assert!(
                original_balances.contains_key(token),
                "Token {} appears in notes but not in original allocation",
                token
            );
        }

        Ok(())
    }
}
