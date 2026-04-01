use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::address::{Address, NetworkChecked, NetworkUnchecked};
use bitcoin::bip39::{DerivationPath, Xpriv};
use bitcoin::{Network, PublicKey};
use clap::Parser;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    about = "Try permutations of 12 BIP-39 words to match a BTC legacy address",
    version
)]
struct Args {
    /// Target legacy Bitcoin address (Base58, starting with '1')
    target_address: String,

    /// Exactly 12 words (unordered or partially ordered)
    words: Vec<String>,

    /// Maximum number of permutations to test
    #[arg(long, default_value_t = 1_000_000)]
    max_permutations: usize,

    /// BIP-39 wordlist language
    #[arg(long, short, default_value = "english")]
    language: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.words.len() != 12 {
        anyhow::bail!("Expected exactly 12 words, got {}", args.words.len());
    }

    let target_address_unchecked = args
        .target_address
        .parse::<Address<NetworkUnchecked>>()
        .context("Invalid target Bitcoin address")?;

    let target_address: Address<NetworkChecked> = target_address_unchecked
        .require_network(Network::Bitcoin.into())
        .context("Only mainnet legacy addresses supported")?;

    let mut words = args.words.clone();

    let start = Instant::now();
    let language = parse_language(&args.language)?;

    let found = search_permutations(
        &mut words,
        &target_address,
        args.max_permutations,
        language,
    )?;

    let elapsed = start.elapsed();

    if !found {
        println!(
            "No match found in {} permutations (elapsed: {:?})",
            format_number(args.max_permutations),
            elapsed
        );
    }

    Ok(())
}

fn format_number(n: usize) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn parse_language(lang: &str) -> Result<Language> {
    match lang.to_lowercase().as_str() {
        "english" => Ok(Language::English),
        "portuguese" => Ok(Language::Portuguese),
        "spanish" => Ok(Language::Spanish),
        "french" => Ok(Language::French),
        "italian" => Ok(Language::Italian),
        "czech" => Ok(Language::Czech),
        "korean" => Ok(Language::Korean),
        "japanese" => Ok(Language::Japanese),
        "chinese-simplified" => Ok(Language::SimplifiedChinese),
        "chinese-traditional" => Ok(Language::TraditionalChinese),
        _ => anyhow::bail!("Unknown language: {}", lang),
    }
}

fn search_permutations(
    words: &mut [String],
    target: &Address<NetworkChecked>,
    max_permutations: usize,
    language: Language,
) -> Result<bool> {
    let derivation_path: DerivationPath = "m/44'/0'/0'/0/0".parse()?;
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut count = 0;
    let mut c = vec![0; words.len()];

    // primeira permutação
    if check(words, target, &secp, &derivation_path, language, count)? {
        return Ok(true);
    }
    count += 1;

    let mut i = 0;
    while i < words.len() {
        if count >= max_permutations {
            break;
        }

        if c[i] < i {
            if i % 2 == 0 {
                words.swap(0, i);
            } else {
                words.swap(c[i], i);
            }

            if count % 100000 == 0 && count > 0 {
                println!("Checked {} permutations...", format_number(count));
            }

            if check(words, target, &secp, &derivation_path, language, count)? {
                return Ok(true);
            }

            count += 1;
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }

    Ok(false)
}

fn check(
    words: &[String],
    target: &Address<NetworkChecked>,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    derivation_path: &DerivationPath,
    language: Language,
    index: usize,
) -> Result<bool> {
    let phrase = words.join(" ");

    let mnemonic = match Mnemonic::parse_in_normalized(language, &phrase) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    let seed = mnemonic.to_seed("");

    let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let child_xprv = master_xprv.derive_priv(secp, derivation_path)?;

    let child_pub = PublicKey::new(child_xprv.private_key.public_key(secp));
    let addr = Address::p2pkh(&child_pub, Network::Bitcoin);

    if &addr == target {
        println!("\n🎉 FOUND MATCH!");
        println!("Mnemonic: {}", phrase);
        println!("Index: {}", index);
        println!("Address: {}", addr);
        return Ok(true);
    }

    Ok(false)
}
