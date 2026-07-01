use std::env;
use std::fs;
use serde::{Deserialize, Serialize};
use serde_json::json;
use num_bigint::BigUint;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::utils::biguint_to_fe;

use circuits::{
    assign_muungano_circuit, native_compute_root, native_leaf_hash,
    MuunganoPrivateWitness, MuunganoPublicInputs, DEFAULT_K, DEFAULT_LOOKUP_BITS
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CliInputs {
    public_root_1: String,
    public_root_2: String,
    public_threshold: String,
    public_quote_id: String,
    
    private_score_1: String,
    private_salt_1: String,
    private_path_1: Vec<String>,
    private_index_1: String,

    private_score_2: String,
    private_salt_2: String,
    private_path_2: Vec<String>,
    private_index_2: String,

    private_identity: String,
}

fn parse_fr(s: &str) -> Fr {
    let clean = s.trim();
    let bigint = if clean.starts_with("0x") || clean.starts_with("0X") {
        BigUint::parse_bytes(clean[2..].as_bytes(), 16)
            .expect("Invalid hex string for Fr")
    } else {
        BigUint::parse_bytes(clean.as_bytes(), 10)
            .expect("Invalid decimal string for Fr")
    };
    biguint_to_fe(&bigint)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  circuits prove <input_json_path>");
        eprintln!("  circuits verify <proof_json_path>");
        eprintln!("  circuits generate-mock-tree <score_1> <score_2> <threshold> <quote_id>");
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "prove" => {
            if args.len() < 3 {
                eprintln!("Error: missing input json path");
                std::process::exit(1);
            }
            let input_path = &args[2];
            let input_content = fs::read_to_string(input_path)
                .expect("Failed to read input JSON file");
            
            let raw_inputs: CliInputs = serde_json::from_str(&input_content)
                .expect("Failed to parse inputs JSON");

            // Convert raw input strings to Fr
            let public_root_1 = parse_fr(&raw_inputs.public_root_1);
            let public_root_2 = parse_fr(&raw_inputs.public_root_2);
            let public_threshold = parse_fr(&raw_inputs.public_threshold);
            let public_quote_id = parse_fr(&raw_inputs.public_quote_id);

            let private_score_1 = parse_fr(&raw_inputs.private_score_1);
            let private_salt_1 = parse_fr(&raw_inputs.private_salt_1);
            let private_index_1 = parse_fr(&raw_inputs.private_index_1);

            let private_score_2 = parse_fr(&raw_inputs.private_score_2);
            let private_salt_2 = parse_fr(&raw_inputs.private_salt_2);
            let private_index_2 = parse_fr(&raw_inputs.private_index_2);

            let private_identity = parse_fr(&raw_inputs.private_identity);

            let mut private_path_1 = [Fr::from(0); 4];
            let mut private_path_2 = [Fr::from(0); 4];
            for i in 0..4 {
                private_path_1[i] = parse_fr(&raw_inputs.private_path_1[i]);
                private_path_2[i] = parse_fr(&raw_inputs.private_path_2[i]);
            }

            let public = MuunganoPublicInputs {
                public_root_1,
                public_root_2,
                public_threshold,
                public_quote_id,
            };

            let private = MuunganoPrivateWitness {
                private_score_1,
                private_salt_1,
                private_path_1,
                private_index_1,
                
                private_score_2,
                private_salt_2,
                private_path_2,
                private_index_2,

                private_identity,
            };

            // Run circuit setup and MockProver to verify constraints
            let mut builder = RangeCircuitBuilder::default()
                .use_k(DEFAULT_K as usize)
                .use_lookup_bits(DEFAULT_LOOKUP_BITS);
            builder.set_instance_columns(1);

            let range = RangeChip::new(DEFAULT_LOOKUP_BITS, builder.lookup_manager().clone());
            let mut assigned_instances = Vec::new();
            assign_muungano_circuit(builder.pool(0), &range, public.clone(), private, &mut assigned_instances);
            builder.assigned_instances[0] = assigned_instances;

            builder.calculate_params(Some(9));

            let public_inputs = vec![vec![public_root_1, public_root_2, public_threshold, public_quote_id]];
            let prover = MockProver::run(DEFAULT_K, &builder, public_inputs).unwrap();

            match prover.verify() {
                Ok(_) => {
                    let proof_output = json!({
                        "status": "success",
                        "public_inputs": {
                            "public_root_1": raw_inputs.public_root_1,
                            "public_root_2": raw_inputs.public_root_2,
                            "public_threshold": raw_inputs.public_threshold,
                            "public_quote_id": raw_inputs.public_quote_id,
                        },
                        "witness_proof": {
                            "private_score_1": raw_inputs.private_score_1,
                            "private_salt_1": raw_inputs.private_salt_1,
                            "private_path_1": raw_inputs.private_path_1,
                            "private_index_1": raw_inputs.private_index_1,
                            
                            "private_score_2": raw_inputs.private_score_2,
                            "private_salt_2": raw_inputs.private_salt_2,
                            "private_path_2": raw_inputs.private_path_2,
                            "private_index_2": raw_inputs.private_index_2,

                            "private_identity": raw_inputs.private_identity,
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&proof_output).unwrap());
                }
                Err(e) => {
                    eprintln!("ZK Proof Generation failed: constraints not satisfied!");
                    eprintln!("{:?}", e);
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            if args.len() < 3 {
                eprintln!("Error: missing proof json path");
                std::process::exit(1);
            }
            let proof_path = &args[2];
            let proof_content = fs::read_to_string(proof_path)
                .expect("Failed to read proof JSON file");
            
            let proof_data: serde_json::Value = serde_json::from_str(&proof_content)
                .expect("Failed to parse proof JSON");

            if proof_data["status"] != "success" {
                println!("false");
                std::process::exit(0);
            }

            let public_inputs = &proof_data["public_inputs"];
            let witness_proof = &proof_data["witness_proof"];

            let public_root_1 = parse_fr(public_inputs["public_root_1"].as_str().unwrap());
            let public_root_2 = parse_fr(public_inputs["public_root_2"].as_str().unwrap());
            let public_threshold = parse_fr(public_inputs["public_threshold"].as_str().unwrap());
            let public_quote_id = parse_fr(public_inputs["public_quote_id"].as_str().unwrap());

            let private_score_1 = parse_fr(witness_proof["private_score_1"].as_str().unwrap());
            let private_salt_1 = parse_fr(witness_proof["private_salt_1"].as_str().unwrap());
            let private_index_1 = parse_fr(witness_proof["private_index_1"].as_str().unwrap());

            let private_score_2 = parse_fr(witness_proof["private_score_2"].as_str().unwrap());
            let private_salt_2 = parse_fr(witness_proof["private_salt_2"].as_str().unwrap());
            let private_index_2 = parse_fr(witness_proof["private_index_2"].as_str().unwrap());

            let private_identity = parse_fr(witness_proof["private_identity"].as_str().unwrap());

            let mut private_path_1 = [Fr::from(0); 4];
            let mut private_path_2 = [Fr::from(0); 4];
            let path_array_1 = witness_proof["private_path_1"].as_array().unwrap();
            let path_array_2 = witness_proof["private_path_2"].as_array().unwrap();
            for i in 0..4 {
                private_path_1[i] = parse_fr(path_array_1[i].as_str().unwrap());
                private_path_2[i] = parse_fr(path_array_2[i].as_str().unwrap());
            }

            let public = MuunganoPublicInputs {
                public_root_1,
                public_root_2,
                public_threshold,
                public_quote_id,
            };

            let private = MuunganoPrivateWitness {
                private_score_1,
                private_salt_1,
                private_path_1,
                private_index_1,
                
                private_score_2,
                private_salt_2,
                private_path_2,
                private_index_2,

                private_identity,
            };

            let mut builder = RangeCircuitBuilder::default()
                .use_k(DEFAULT_K as usize)
                .use_lookup_bits(DEFAULT_LOOKUP_BITS);
            builder.set_instance_columns(1);

            let range = RangeChip::new(DEFAULT_LOOKUP_BITS, builder.lookup_manager().clone());
            let mut assigned_instances = Vec::new();
            assign_muungano_circuit(builder.pool(0), &range, public, private, &mut assigned_instances);
            builder.assigned_instances[0] = assigned_instances;

            builder.calculate_params(Some(9));

            let public_inputs_vec = vec![vec![public_root_1, public_root_2, public_threshold, public_quote_id]];
            let prover = MockProver::run(DEFAULT_K, &builder, public_inputs_vec).unwrap();

            match prover.verify() {
                Ok(_) => println!("true"),
                Err(_) => println!("false"),
            }
        }
        "generate-mock-tree" => {
            if args.len() < 6 {
                eprintln!("Error: missing score_1, score_2, threshold, and quote_id");
                std::process::exit(1);
            }
            let score_1_val = parse_fr(&args[2]);
            let score_2_val = parse_fr(&args[3]);
            let threshold_val = parse_fr(&args[4]);
            let quote_id_val = parse_fr(&args[5]);

            let identity = Fr::from(12345u64);
            
            // Tree 1 values
            let salt_1 = Fr::from(9999u64);
            let leaf_1 = native_leaf_hash(identity, score_1_val, salt_1);
            let path_1 = [
                Fr::from(11u64),
                Fr::from(22u64),
                Fr::from(33u64),
                Fr::from(44u64),
            ];
            let index_1 = 5;
            let root_1 = native_compute_root(leaf_1, &path_1, index_1);

            // Tree 2 values
            let salt_2 = Fr::from(8888u64);
            let leaf_2 = native_leaf_hash(identity, score_2_val, salt_2);
            let path_2 = [
                Fr::from(55u64),
                Fr::from(66u64),
                Fr::from(77u64),
                Fr::from(88u64),
            ];
            let index_2 = 10;
            let root_2 = native_compute_root(leaf_2, &path_2, index_2);

            let output_json = json!({
                "public_root_1": format!("{:?}", root_1),
                "public_root_2": format!("{:?}", root_2),
                "public_threshold": format!("{:?}", threshold_val),
                "public_quote_id": format!("{:?}", quote_id_val),
                
                "private_score_1": format!("{:?}", score_1_val),
                "private_salt_1": format!("{:?}", salt_1),
                "private_path_1": vec![
                    format!("{:?}", path_1[0]),
                    format!("{:?}", path_1[1]),
                    format!("{:?}", path_1[2]),
                    format!("{:?}", path_1[3]),
                ],
                "private_index_1": format!("{:?}", Fr::from(index_1 as u64)),
                
                "private_score_2": format!("{:?}", score_2_val),
                "private_salt_2": format!("{:?}", salt_2),
                "private_path_2": vec![
                    format!("{:?}", path_2[0]),
                    format!("{:?}", path_2[1]),
                    format!("{:?}", path_2[2]),
                    format!("{:?}", path_2[3]),
                ],
                "private_index_2": format!("{:?}", Fr::from(index_2 as u64)),

                "private_identity": format!("{:?}", identity)
            });
            println!("{}", serde_json::to_string_pretty(&output_json).unwrap());
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
