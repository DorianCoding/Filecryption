use base64::{engine::general_purpose, Engine as _};
use inotify::{Inotify, WatchMask};
use orion::aead;
use orion::aead::streaming::*;
use orion::kdf;
use rpassword;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::result::Result;
use std::thread;
use std::time::{self, Duration};
const FILEPARAM: &str = "parameters.txt";
const SALTSIZE: usize = 24;
const CHUNK_SIZE: usize = 128; // The size of the chunks you wish to split the stream into.
const MIN_MEM_ARGON: u8 = 10; //2^10 means 1024 KiB.
const MAX_MEM_ARGON: u8 = 40; //Little more than 10^12 KiB.
fn extractmasterkey(twotime: bool) -> orion::aead::SecretKey {
    let mut salt;
    let mut calc: u8 = 0;
    let file = match File::open(FILEPARAM) {
        Result::Ok(mut f) => {
            let mut buffer = String::new();
            // read the whole file
            f.read_to_string(&mut buffer).unwrap();
            let buffer: Vec<&str> = buffer.split(":").collect();
            if buffer.len() != 2 {
                panic!("Error on reading parameters");
            }
            calc = buffer[0].trim().parse().unwrap();
            if calc < MIN_MEM_ARGON || calc > MAX_MEM_ARGON {
                panic!("Invalid identifier");
            }
            salt =
                kdf::Salt::from_slice(&general_purpose::STANDARD.decode(buffer[1].trim()).unwrap())
                    .unwrap();
        }
        Result::Err(err) => {
            println!("Getting parameter to derive the master key, please wait several seconds.");
            let now = time::Instant::now();
            let user_password = kdf::Password::from_slice(b"This is an attempt").unwrap();
            salt = kdf::Salt::default();
            calc = 0;
            for i in MIN_MEM_ARGON..MAX_MEM_ARGON {
                let derived_key = kdf::derive_key(&user_password, &salt, 3, 1 << i, 32).unwrap();
                //println!("The derived key is {}",general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes()));
                if now.elapsed().as_millis() > 5000 {
                    let base: u32 = 10;
                    println!(
                        "The parameter used would be {} MiB",
                        (1 << (i - 1)) / base.pow(3)
                    );
                    calc = i - 1;
                    break;
                } else {
                    let now = time::Instant::now();
                }
            }
            fs::write(
                FILEPARAM,
                String::from(
                    calc.to_string() + ":" + &general_purpose::STANDARD.encode(salt.as_ref()),
                ),
            )
            .unwrap();
        }
    };
    let mut password;
    let mut passwordorion: orion::pwhash::Password;
    let mut password2;
    let mut password2orion: orion::pwhash::Password;
    loop {
        println!("Enter your master password:");
        password = rpassword::read_password().unwrap();
        passwordorion = kdf::Password::from_slice(&password.as_bytes()).unwrap();
        if twotime {
            println!("Confirm your master password:");
            password2 = rpassword::read_password().unwrap();
            password2orion = kdf::Password::from_slice(&password2.as_bytes()).unwrap();
            if password2orion == passwordorion {
                //Constant-time
                break;
            }
            thread::sleep(Duration::new(2, 0));
            eprintln!("Passwords are not the same, please retry!");
        } else {
            break;
        }
    }
    let derived_key = kdf::derive_key(&passwordorion, &salt, 3, 1 << calc, 32).unwrap();
    /* println!(
        "The master key is: '{}'. Please keep it safe.",
        general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes())
    ); */
    return aead::SecretKey::from_slice(derived_key.unprotected_as_bytes()).unwrap();
}
fn main() {
    let directoryparam: &Path = Path::new("files/");
    /* let envs: Vec<_> = env::args().collect();
    if envs.len() < 2 {
        eprintln!("Lack args, use ./script args (encrypt,decrypt)");
        return;
    } */
    let mut inotify = Inotify::init().expect("Error while initializing inotify instance");
    let secret_key = extractmasterkey(true);
    println!("Listening to file changes...");

    // Read events that were added with `Watches::add` above.
    let mut buffer = [0; 1024];
    loop {
        // Watch for modify and close events.
        inotify
            .watches()
            .add(&directoryparam, WatchMask::MOVED_TO | WatchMask::CREATE)
            .expect("Failed to add file watch");
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("Error while reading events");
        for event in events {
            // Handle event
            match event.name {
                Some(x) => {
                    let newpath = Path::new(&directoryparam).join(&x);
                    let newpath = newpath.as_os_str();
                    inotify
                        .watches()
                        .remove(event.wd)
                        .expect("Failed to add file watch");
                    encryptastream(&secret_key, newpath);
                }
                None => continue,
            };
        }
    }
}
pub fn encryptastream(secret_key: &aead::SecretKey, file: &OsStr) {
    let filedata: String = match file.to_str() {
        Some(x) => String::from(x),
        None => {
            eprintln!("Cannot get correct filename");
            return;
        }
    };
    if filedata.as_str().ends_with("_encrypted") {
        decryptastream(&secret_key, file);
        return;
    }
    let (mut sealer, nonce) = StreamSealer::new(&secret_key).unwrap();
    let data = fs::read(&filedata);
    if data.is_err() {
        eprintln!(
            "The error is {} for the file {:?}",
            data.unwrap_err(),
            &filedata
        );
        return;
    }
    let data = data.unwrap(); //Cannot be wrong
    let mut filename = filedata.clone();
    filename.push_str("_encrypted");
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(filename)
        .unwrap();
    /* println!(
        "The nonce is set! {}",
        general_purpose::STANDARD.encode(nonce.as_ref())
    ); */
    if file.write(nonce.as_ref()).unwrap() != SALTSIZE {
        panic!("Nonce error");
    }
    for (n_chunk, src_chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        let encrypted_chunk =
            if src_chunk.len() != CHUNK_SIZE || n_chunk + 1 == data.len() / CHUNK_SIZE {
                // We've reached the end of the input source,
                // so we mark it with the Finish tag.
                sealer.seal_chunk(src_chunk, &StreamTag::Finish).unwrap()
            } else {
                // Just a normal chunk
                sealer.seal_chunk(src_chunk, &StreamTag::Message).unwrap()
            };
        // Save the encrypted chunk somewhere
        file.write(&encrypted_chunk).expect("Invalid writing.");
    }
    let blank: String = String::new();
    let write = fs::write(&filedata, &blank); //Empty a file
    if write.is_err() {
        eprintln!(
            "The error is {} for the file {:?}",
            write.unwrap_err(),
            &filedata
        );
        return;
    }
    let delete = fs::remove_file(&filedata);
    if delete.is_err() {
        eprintln!(
            "The error is {} for the file {}",
            delete.unwrap_err(),
            &filedata
        );
        return;
    }
    println!("Following file has been encrypted: '{}'.", &filedata);
}
pub fn decryptastream(secret_key: &aead::SecretKey, file: &OsStr) {
    let filedata: String = match file.to_str() {
        Some(x) => String::from(x),
        None => {
            eprintln!("Cannot get correct filename");
            return;
        }
    };
    let decipher_chunk = CHUNK_SIZE + ABYTES;
    if !filedata.as_str().ends_with("_encrypted") {
        return;
    }
    let nonce = fs::read(&filedata);
    if nonce.is_err() {
        eprintln!(
            "The error is {} for the file {:?}",
            nonce.unwrap_err(),
            &filedata
        );
        return;
    }
    let mut nonce = nonce.unwrap(); //Cannot be wrong
    if nonce.len() < SALTSIZE {
        eprintln!("Lack characters to decrypt for the file {:?}", &filedata);
        return;
    }
    let data = nonce.split_off(SALTSIZE);
    let nonce: orion::hazardous::stream::xchacha20::Nonce =
        orion::hazardous::stream::xchacha20::Nonce::from_slice(&nonce).unwrap();
    /* println!(
        "The nonce is set! {}",
        general_purpose::STANDARD.encode(&nonce)
    ); */
    let mut opener = StreamOpener::new(&secret_key, &nonce).unwrap();
    let out: Vec<Vec<u8>> = Vec::with_capacity(data.len() / decipher_chunk);
    let mut filename = filedata.clone();
    filename = String::from(filename.as_str().trim_end_matches("_encrypted")); //Remove last _encrypted
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(&filename);
    if file.is_err() {
        eprintln!(
            "The error is {} for the file {:?}",
            file.unwrap_err(),
            &filename
        );
        return;
    }
    let mut file = file.unwrap();
    let mut error = false;
    for (n_chunk, src_chunk) in data.chunks(decipher_chunk).enumerate() {
        let openerfile = opener.open_chunk(src_chunk);
        if openerfile.is_err() {
            fs::remove_file(&filename); //Remove invalid file created
            eprintln!(
                "The error is {} for the file {:?}",
                openerfile.unwrap_err(),
                &filedata
            );
            error = true;
            break;
        }
        let (decrypted_chunk, tag) = openerfile.unwrap();
        if src_chunk.len() != CHUNK_SIZE + ABYTES || n_chunk + 1 == out.len() {
            // We've reached the end of the input source,
            // so we check if the last chunk is also set as Finish.
            assert_eq!(tag, StreamTag::Finish, "Stream has been truncated!");
        }
        // Save the encrypted chunk somewhere
        file.write(&decrypted_chunk).expect("Invalid writing");
    }
    if error {
        //error
        return;
    }
    let blank: String = String::new();
    let write = fs::write(&filedata, &blank);
    if write.is_err() {
        eprintln!(
            "The error is {} for the file {:?}",
            write.unwrap_err(),
            &filedata
        );
        return;
    }
    /* let write = fs::write(&filename, &out);
    if write.is_err() {
        eprintln!("Bad write on file {:?}", &filedata);
        continue;
    } */
    let delete = fs::remove_file(&filedata);
    if delete.is_err() {
        eprintln!(
            "The error is {} for the file {}",
            delete.unwrap_err(),
            &filedata
        );
        return;
    }
    println!("The file {} has been decrypted successfully.", &filedata);
}
