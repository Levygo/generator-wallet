// Thread
use std::thread;

// Bitcoin
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::util::address::Address;
use bitcoin::util::ecdsa;
use bitcoin::{PrivateKey, PublicKey};

// File
use std::io::{prelude::*, BufReader};
use std::path::Path;
use std::str::FromStr;

// Util
use anyhow::Result;
use clap::Parser;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

fn main() {
    let logotype = r#"         ...     ..            ..                                                 
  .=*8888x <"?88h.   x .d88"                                        .uef^"    
 X>  '8888H> '8888    5888R                 .u    .               :d88E       
'88h. `8888   8888    '888R        .u     .d88B :@8c       uL     `888E       
'8888 '8888    "88>    888R     ud8888.  ="8888f8888r  .ue888Nc..  888E .z8k  
 `888 '8888.xH888x.    888R   :888'8888.   4888>'88"  d88E`"888E`  888E~?888L 
   X" :88*~  `*8888>   888R   d888 '88%"   4888> '    888E  888E   888E  888E 
 ~"   !"`      "888>   888R   8888.+"      4888>      888E  888E   888E  888E 
  .H8888h.      ?88    888R   8888L       .d888L .+   888E  888E   888E  888E 
 :"^"88888h.    '!    .888B . '8888c. .+  ^"8888*"    888& .888E   888E  888E 
 ^    "88888hx.+"     ^*888%   "88888%       "Y"      *888" 888&  m888N= 888> 
        ^"**""          "%       "YP'                  `"   "888E  `Y"   888  
                                                      .dWi   `88E       J88"  
                                                      4888~  J8%        @%    
                                                       ^"===*"`       :"      
"#;

    println!("{}(-h / --help)", logotype);

    let mut cfg = Config::parse();
    if cfg.cpu_count == 0 {
        cfg.cpu_count = determine_cpus();
    }
    (0..cfg.cpu_count).for_each(|idx| {
        start_gen(idx, &cfg.source_file, cfg.verbose);
    });
    thread::sleep(Duration::from_millis(10));
    loop {
        thread::sleep(Duration::from_secs(cfg.update_timeout));
        // println!("Updating addresses");
        if let Err(e) = update_addr_db(&cfg.source_file) {
            println!("{}", e)
        };
    }
}

/// Brute-force BTC wallet generator and checker
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Config {
    /// Path to file with target addresses
    #[clap(short, long, default_value = "addr.txt")]
    source_file: String,

    /// Number of cpus to use (0-auto)
    #[clap(short, long, default_value = "0")]
    cpu_count: usize,

    /// Print wallets while generating
    #[clap(short, long)]
    verbose: bool,

    /// Time (in seconds) to wait between target file updates
    #[clap(short, long, default_value = "600")]
    update_timeout: u64,
}

fn determine_cpus() -> usize {
    let cpu_count = num_cpus::get();
    let mut cpu_use = cpu_count;
    if cpu_count > 1 {
        cpu_use -= 1;
    };
    println!("Using {}/{} CPUs", &cpu_use, &cpu_count);
    cpu_use
}

fn start_gen(thread_idx: usize, file: &str, verbose: bool) {
    let file = file.to_string();
    thread::spawn(move || {
        let address_db = load_address_map(file).expect("Failed to load addresses");
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");

        println!("[Gen_{:02}] is UP️", &thread_idx);
        if verbose {
            loop {
                let wallet = new_wallet(&secp, &mut rng);
                println!("{}", &wallet);
                check_wallet(&wallet, &address_db);
            }
        } else {
            loop {
                let wallet = new_wallet(&secp, &mut rng);
                check_wallet(&wallet, &address_db);
            }
        }
    });
}

fn load_address_map(path: impl AsRef<Path>) -> Result<HashSet<Address>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .expect("No such file");
    let buf = BufReader::new(file);
    let data: HashSet<Address> = buf
        .lines()
        .map(|line| {
            Address::from_str(&line.expect("Could not parse line")).expect("Incorrect address")
        })
        .collect();
    Ok(data)
}

fn load_string_map(path: impl AsRef<Path>) -> Result<HashSet<String>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .expect("No such file");
    let buf = BufReader::new(file);
    let data: HashSet<String> = buf
        .lines()
        .map(|line| line.expect("Could not parse line"))
        .collect();
    Ok(data)
}

#[derive(Debug, PartialEq, Eq)]
struct Wallet {
    secret_key: SecretKey,
    private_key: PrivateKey,
    public_key: PublicKey,
    // address: Address,
    addr_p2pkh: Address,
    addr_p2shwpkh: Address,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{}",
            self.secret_key, self.private_key, self.public_key, self.addr_p2pkh, self.addr_p2shwpkh
        )
    }
}

fn new_wallet(secp: &Secp256k1<All>, rng: &mut OsRng) -> Wallet {
    // Generate secp keypair, this is the slowest part of this function
    // Should be optimized if possible
    let (secret_key, public_key) = secp.generate_keypair(rng);

    // Generates only keys from certain range which is not good. To be fixed
    let private_key = ecdsa::PrivateKey::new(secret_key, Network::Bitcoin);
    let public_key = ecdsa::PublicKey::new(public_key);

    // Generate address
    let addr_p2pkh = Address::p2pkh(&public_key, Network::Bitcoin);
    let addr_p2shwpkh =
        Address::p2shwpkh(&public_key, Network::Bitcoin).expect("Failed to generate address");
    Wallet {
        secret_key,
        private_key,
        public_key,
        addr_p2pkh,
        addr_p2shwpkh,
    }
}

fn check_wallet(wallet: &Wallet, address_db: &HashSet<Address>) -> bool {
    if address_db.contains(&wallet.addr_p2pkh) | address_db.contains(&wallet.addr_p2shwpkh) {
        println!("Found one!");
        save_wallet(wallet).expect("Failed to save");
        true
    } else {
        false
    }
}

fn save_wallet(wallet: &Wallet) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("success.txt")
        .expect("No such file");
    let message = format!(
        "ADDR_P2PKH:\t{}\nADDR_P2SHWPKH:\t{}\nSECRET:\t{}\n========================================================================\n",
        wallet.addr_p2pkh, wallet.addr_p2shwpkh, wallet.secret_key
    );
    file.write_all(message.as_bytes())
        .expect("Failed to write to file");
    Ok(())
}

fn update_addr_db(path: impl AsRef<Path> + Copy) -> Result<()> {
    let last_hash = get_last_block_hash_string().expect("API limits exceeded");
    let transacions = get_transactions(&last_hash)?;
    let address_string_map = load_string_map(path)?;
    for txid in transacions {
        let addresses = get_addresses(&txid)?;
        // println!("{:?}", addresses);
        add_addresses_to_db(path, addresses, &address_string_map)?;
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn add_addresses_to_db(
    path: impl AsRef<Path>,
    addresses: Vec<Value>,
    address_string_map: &HashSet<String>,
) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .expect("No such file");
    let mut message = "".to_owned();
    for addr in addresses {
        let addr_str = addr.as_str().expect("Failed to parse address");
        if !address_string_map.contains(addr_str) && &addr_str[..2] != "bc" {
            message = format!("{}\n", addr_str);
            println!("Adding addresses to list:\n{}", addr_str);
        }
    }
    file.write_all(message.as_bytes())
        .expect("Failed to write to file");
    Ok(())
}

fn get_last_block_hash_string() -> Result<Value> {
    let blockchain: Value = serde_json::from_str(
        &reqwest::blocking::get("https://api.blockcypher.com/v1/btc/main")?.text()?,
    )?;
    match blockchain.get("error") {
        Some(e) => {
            println!("{}", e);
            panic!("Limits exceeded")
        }
        None => {
            let hash = blockchain
                .get("previous_hash")
                .expect("Failed to retrieve hash")
                .to_owned();

            Ok(hash)
        }
    }
}

fn get_transactions(block_hash: &Value) -> Result<Vec<Value>> {
    let tx_hashes: Value = serde_json::from_str(
        &reqwest::blocking::get(format!(
            "https://api.blockcypher.com/v1/btc/main/blocks/{}",
            block_hash.as_str().unwrap()
        ))?
        .text()?,
    )?;
    let tx_list = tx_hashes
        .get("txids")
        .expect("Failed to retrieve transactions")
        .as_array()
        .expect("Failed to parse")
        .to_vec();
    // println!("txs:{:#?}", tx_hashes);
    Ok(tx_list)
}

fn get_addresses(txid: &Value) -> Result<Vec<Value>> {
    let addr_list_obj: Value = serde_json::from_str(
        &reqwest::blocking::get(format!(
            "https://api.blockcypher.com/v1/btc/main/txs/{}",
            txid.as_str().unwrap()
        ))?
        .text()?,
    )?;
    let addresses: Vec<Value> = addr_list_obj
        .get("addresses")
        .expect("Failed to retrieve addresses")
        .as_array()
        .expect("Failed to parse")
        .to_vec();
    // println!("addr:{:#?}", addresses);
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gethash() {
        assert!(get_last_block_hash_string().is_ok());
    }

    #[test]
    fn gettx() {
        assert!(get_transactions(&get_last_block_hash_string().unwrap()).is_ok());
    }

    #[test]
    fn save() {
        let secret_key =
            SecretKey::from_str("0f4deefc27293f17822971c262f30617996953916e790419c715f2c7edca47ba")
                .unwrap();
        let private_key =
            PrivateKey::from_str("KwjTg1e6MLpzk65cVGSVynyKhLuDdEqiG2Er7Qa6v3GmnHoiWvqs").unwrap();
        let public_key = PublicKey::from_str(
            "0251d78dcdb288cf384406579f635ccd244212fa686a058de595582f4c0e1e40fd",
        )
        .unwrap();
        let addr1 = Address::p2pkh(&public_key, Network::Bitcoin);
        let addr2 = Address::p2shwpkh(&public_key, Network::Bitcoin).unwrap();
        let wallet = Wallet {
            secret_key,
            private_key,
            public_key,
            addr_p2pkh: addr1,
            addr_p2shwpkh: addr2,
        };
        println!("{}", &wallet);
        let address_db = load_address_map("addr.txt").unwrap();
        assert!(check_wallet(&wallet, &address_db));
    }
}
