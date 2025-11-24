use serde_json::{self, json, Value};
use std::{
    path::Path,
    {env, fs},
};

fn get_cli_args() -> Result<(String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "provide the following flags: {} <input-file> <address>",
            args[0]
        );
        std::process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone()))
}

/// # create geneisis notes: Sinsemilla HashDomain
/// - generates default note using posiedon hashing algo & Fixed-Denomination Notes
/// - loads all balances,
/// - creates genesis Fixed-Denomination Notes, containing
///     -  tuple of static value: (1_000_000_000,100_000_000,10_000_000,1_000_000, ..) & index (multiple of notes an key is allocated per static value)\
///
///
/// ```
///  cargo run -- --bin create_genesis_notes ./data/genesis_sinsemilla.json 0x0000000000000000000000000000000000000000
/// ```
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (input_path, addr_target) = get_cli_args()?;
    let input_data: Value = serde_json::from_str(&fs::read_to_string(&input_path)?)?;

    let mut address_notes = serde_json::Map::new();

    if let Value::Object(map) = &input_data {
        if let Some(holdings) = map.get(&addr_target) {
            if let Value::Array(holding_array) = holdings {
                for holding in holding_array.iter() {
                    // token identifier: raw value ("uterp", "ibc/...", "tokenfactory/...")
                    let token_name = holding["name"].as_str().unwrap().to_string();
                    let _total_amount = holding["amount"].as_str().unwrap();

                    let leaves = match holding.get("leaves") {
                        Some(Value::Array(arr)) => arr,
                        _ => {
                            eprintln!("⚠️  No \"leaves\" array for token {}", token_name);
                            std::process::exit(1);
                        }
                    };

                    let mut generated_notes = Vec::new();

                    for leaf in leaves.iter() {
                        // concrete amount for this note
                        let amnt = leaf["amnt"].as_u64().unwrap_or_else(|| {
                            eprintln!("⚠️  Missing \"amnt\" in leaf for token {}", token_name);
                            std::process::exit(1);
                        });

                        // the fdi value (the leaf itself)
                        let fdi = leaf["index"].as_u64().unwrap_or_else(|| {
                            eprintln!("⚠️  Missing \"index\" in leaf for token {}", token_name);
                            std::process::exit(1);
                        });

                        // ------------------------------------------------------------------
                        // 2️⃣  Build a NoteTemplate‑compatible JSON object
                        // ------------------------------------------------------------------
                        generated_notes.push(json!({
                            "m":          "",
                            "e_sk":    &addr_target,
                            "nul_sk":     "",
                            "sig_jub":    "",
                            "fdi":        fdi,
                            "amount":     amnt.to_string(),
                            "denom":      token_name.clone(),
                            "recp":       "",
                            "nul":   "",
                            "e_pk":     "",
                            "ψ":          "",
                            "note_cm":    ""
                        }));
                    }

                    // ------------------------------------------------------------------
                    // 3️⃣  Insert the array of notes for this token into the final map
                    // ------------------------------------------------------------------
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
        eprintln!("Error: Input data is not a JSON object.");
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

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
