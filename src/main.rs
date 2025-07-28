use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use rand::RngCore;
use aes_gcm::AeadCore;
use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead, Write},
    path::Path,
};

const STORE_PATH: &str = "password_store.json";
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Debug, Default)]
struct PasswordEntry {
    label: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct PasswordStore {
    entries: HashMap<String, PasswordEntry>,
}

fn derive_key(master_pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<HmacSha256>(master_pass.as_bytes(), salt, 100_000, &mut key);
    key
}

fn encrypt_password(master_pass: &str, plain_pass: &str) -> PasswordEntry {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key_bytes = derive_key(master_pass, &salt);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plain_pass.as_bytes())
        .expect("Encryption failed");

    PasswordEntry {
        label: String::new(),
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    }
}

fn decrypt_password(master_pass: &str, entry: &PasswordEntry) -> Option<String> {
    let salt = general_purpose::STANDARD.decode(&entry.salt).ok()?;
    let nonce = general_purpose::STANDARD.decode(&entry.nonce).ok()?;
    let ciphertext = general_purpose::STANDARD.decode(&entry.ciphertext).ok()?;

    let key_bytes = derive_key(master_pass, &salt);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce);

    cipher.decrypt(nonce, ciphertext.as_ref()).ok().and_then(|bytes| String::from_utf8(bytes).ok())
}

fn generate_password(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn load_store() -> PasswordStore {
    if !Path::new(STORE_PATH).exists() {
        return PasswordStore::default();
    }

    let content = fs::read_to_string(STORE_PATH).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_store(store: &PasswordStore) {
    let json = serde_json::to_string_pretty(store).expect("Failed to serialize store");
    fs::write(STORE_PATH, json).expect("Failed to write store file");
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).unwrap();
    input.trim().to_owned()
}

fn pause() {
    println!("Press Enter to continue...");
    let _ = io::stdin().read_line(&mut String::new());
}

fn main() {
    let mut store = load_store();

    loop {
        println!("\n=== Password Manager ===");
        println!("1) Create and encrypt password");
        println!("2) Decrypt saved password");
        println!("3) Show saved labels");
        println!("4) Quit");

        let choice = prompt("Option: ");

        match choice.as_str() {
            "1" => {
                let label = prompt("Label for password (e.g. email, bank): ");
                let len_input = prompt("Password length (default 16): ");
                let length = len_input.parse::<usize>().unwrap_or(16);

                let new_pass = generate_password(length);
                println!("New password: {}", new_pass);

                let master_pass = prompt("Master password for encryption: ");
                let mut entry = encrypt_password(&master_pass, &new_pass);
                entry.label = label.clone();

                store.entries.insert(label, entry);
                save_store(&store);

                println!("Password saved securely.");
            }
            "2" => {
                let label = prompt("Label to decrypt: ");
                match store.entries.get(&label) {
                    Some(entry) => {
                        let master_pass = prompt("Master password for decryption: ");
                        match decrypt_password(&master_pass, entry) {
                            Some(pass) => println!("Decrypted password: {}", pass),
                            None => println!("Decryption failed: Wrong password or corrupted data."),
                        }
                    }
                    None => println!("No entry found for '{}'.", label),
                }
            }
            "3" => {
                if store.entries.is_empty() {
                    println!("No passwords stored yet.");
                } else {
                    println!("Stored labels:");
                    for label in store.entries.keys() {
                        println!(" - {}", label);
                    }
                }
            }
            "4" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid option."),
        }

        pause();
    }
}