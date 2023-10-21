use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, ValueEnum};
use orion::aead;
use orion::aead::streaming::*;
use orion::kdf;
use rpassword;
use std::ffi::OsStr;
use std::fs::{self, read_dir, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::result::Result;
use std::thread;
use std::time::{self, Duration};
const FILEPARAM: &str = ".parameters.txt";
const SALTSIZE: usize = 24;
const CHUNK_SIZE: usize = 128; // The size of the chunks you wish to split the stream into.
const MIN_MEM_ARGON: u8 = 5;
const MAX_MEM_ARGON: u8 = 100;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Action to perform
    #[clap(value_enum, value_parser)]
    action: Action,

    /// Argon parameter (default should be fit, but can be computed with -t), set exponential for argon, must be between 5 (very low - low CPU devices) and 50 (nearly impossible to compute).
    #[arg(short, long, default_value_t = 15, value_parser = clap::value_parser!(u8).range(i64::from(MIN_MEM_ARGON)..=i64::from(MAX_MEM_ARGON)))]
    argon2: u8,

    /// File(s)/Directories to encrypt/decrypt
    #[arg(value_parser)]
    file: Vec<String>,

    /// Password input
    #[arg(short, long)]
    password: Option<String>,

    ///Recursive all directories and files
    #[arg(short, long)]
    recursive: bool,

    ///verbose mode
    #[clap(short, long)]
    verbose: bool,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Action {
    Encrypt,
    Decrypt,
    Compute,
}
fn extractmasterkey(
    twotime: bool,
    path: &Path,
    argon2: u8,
    password: Option<String>,
) -> orion::aead::SecretKey {
    let mut salt;
    let mut calc: u8 = 0;
    let file = match File::open(path) {
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
            if twotime {
                eprintln!("Parameters file cannot be found! Cannot decrypt.");
                exit(1);
            } else {
                salt = kdf::Salt::generate(SALTSIZE).expect("Cannot generate secure salt");
                calc = argon2;
                let text = format!("{}:{}", calc, &general_purpose::STANDARD.encode(&salt));
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path).expect(&format!("Error creating params file : {:?}",path.file_name()));
                file.write(text.as_bytes()).expect("Cannot write params");
            }
        }
    };
    let mut passwordorion: orion::pwhash::Password;
    match password {
        Some(password) => {
            passwordorion = kdf::Password::from_slice(&password.as_bytes()).unwrap();
        }
        None => {
            let mut password2;
            let mut password2orion: orion::pwhash::Password;
            loop {
                println!("Enter your master password:");
                let password = rpassword::read_password().unwrap();
                passwordorion = kdf::Password::from_slice(&password.as_bytes()).unwrap();
                if twotime {
                    println!("Confirm your master password:");
                    password2 = rpassword::read_password().unwrap();
                    password2orion = kdf::Password::from_slice(&password2.as_bytes()).unwrap();
                    if password2orion == passwordorion {
                        //Constant-time
                        break;
                    }
                    thread::sleep(Duration::new(3, 0));
                    eprintln!("Passwords are not the same, please retry!");
                } else {
                    break;
                }
            }
        }
    };
    let derived_key = kdf::derive_key(&passwordorion, &salt, 3, 1 << calc, 32).unwrap();
    /* println!(
        "The master key is: '{}'. Please keep it safe.",
        general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes())
    ); */
    return aead::SecretKey::from_slice(derived_key.unprotected_as_bytes()).unwrap();
}
fn recurse_files(path: impl AsRef<Path>) -> std::io::Result<Vec<PathBuf>> {
    let mut buf = vec![];
    let entries = read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;

        if meta.is_dir() {
            let mut subdir = recurse_files(entry.path())?;
            buf.append(&mut subdir);
        }

        if meta.is_file() {
            buf.push(entry.path());
        }
    }
    Ok(buf)
}
fn main() {
    let args = Args::parse();
    let mut files: Vec<PathBuf> = Vec::new();
    let filepaths: Vec<String> = args.file;
    let verbose: bool = args.verbose;
    let recursive: bool = args.recursive;
    let mut params: String = String::new();
    for file in filepaths {
        let path = Path::new(&file);
        let result = path.try_exists().expect("Cannot access this file");
        if !result {
            eprintln!("The file {} is not readable.", file);
            exit(1);
        } else {
            match path.file_name() {
                Some(filecheck) => {
                    if filecheck == OsStr::new(".parameters.txt") {
                        params = file;
                        continue;
                    }
                }
                None => {
                    eprintln!("The file {} is not readable.", file);
                    exit(1);
                }
            }
            if path.is_dir() && recursive {
                let dirs = &mut recurse_files(&file);
                match dirs {
                    Ok(dir) => {
                        files.append(dir);
                    }
                    Err(err) => {
                        eprintln!("The directory {} has an error: {:?}", file, err);
                    }
                }
            } else if path.is_dir() {
                if verbose {
                    println!(
                        "The directory {} will be skipped in non-recursive mode",
                        file
                    );
                }
                continue;
            }
            files.push(PathBuf::from(file));
        }
    }
    let fileparam: &Path = match Path::new(&params).try_exists() {
        Ok(result) => {
            if result {
                Path::new(&params)
            } else {
                Path::new(FILEPARAM)
            }
        },
        Err(_) => {
            Path::new(FILEPARAM)
        }
    };
    match args.action {
        Action::Encrypt => {
            let secret_key = extractmasterkey(false, &fileparam, args.argon2, args.password);
            encryptastream(&secret_key, files, recursive, verbose);
        }
        Action::Decrypt => {
            let secret_key = extractmasterkey(true, &fileparam, args.argon2, args.password);
            decryptastream(&secret_key, files, recursive, verbose);
            match fs::remove_file(&fileparam) {
                Ok(_) => {},
                Err(_) => {
                    eprintln!("Cannot delete parameters");
                }
            }
        }
        Action::Compute => {
            if verbose {
                println!(
                    "Getting parameter to derive the master key, please wait several seconds."
                );
            }
            let now = time::Instant::now();
            let user_password = kdf::Password::from_slice(b"This is an attempt").unwrap();
            let salt = kdf::Salt::default();
            let calc = 0;
            for i in MIN_MEM_ARGON..MAX_MEM_ARGON {
                let derived_key = kdf::derive_key(&user_password, &salt, 3, 1 << i, 32).unwrap();
                //println!("The derived key is {}",general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes()));
                if now.elapsed().as_millis() > 5000 {
                    let base: u32 = 10;
                    let calc = i - 1;
                    if verbose {
                        println!(
                            "The parameter used should be {} which corresponds to {} MiB",
                            calc,
                            (1 << calc) / base.pow(3)
                        );
                    } else {
                        println!("{}", calc);
                    }
                    break;
                } else {
                    let now = time::Instant::now();
                }
            }
        }
    }
}
pub fn encryptastream(
    secret_key: &aead::SecretKey,
    files: Vec<PathBuf>,
    recursive: bool,
    verbose: bool,
) {
    for file in files {
        let filedata: String = match file.to_str() {
            Some(x) => String::from(x),
            None => {
                eprintln!("Cannot get correct filename");
                return;
            }
        };
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
            eprintln!("Nonce error");
            exit(1);
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
            continue;
        }
        let delete = fs::remove_file(&filedata);
        if delete.is_err() {
            eprintln!(
                "The error is {} for the file {}. Deletion impossible",
                delete.unwrap_err(),
                &filedata
            );
            continue;
        }
        if verbose {
            println!("Following file has been encrypted: '{}'.", &filedata);
        }
    }
}
pub fn decryptastream(
    secret_key: &aead::SecretKey,
    files: Vec<PathBuf>,
    recursive: bool,
    verbose: bool,
) {
    for file in files {
        let filedata: String = match file.to_str() {
            Some(x) => String::from(x),
            None => {
                eprintln!("Cannot get correct filename");
                continue;
            }
        };
        let decipher_chunk = CHUNK_SIZE + ABYTES;
        let nonce = fs::read(&filedata);
        if nonce.is_err() {
            eprintln!(
                "The error is {} for the file {:?}",
                nonce.unwrap_err(),
                &filedata
            );
            continue;
        }
        let mut nonce = nonce.unwrap(); //Cannot be wrong
        if nonce.len() < SALTSIZE {
            eprintln!("Lack characters to decrypt for the file {:?}", &filedata);
            continue;
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
            continue;
        }
        let mut file = file.unwrap();
        let mut error = false;
        for (n_chunk, src_chunk) in data.chunks(decipher_chunk).enumerate() {
            let openerfile = opener.open_chunk(src_chunk);
            if openerfile.is_err() {
                fs::remove_file(&filename); //Remove invalid file created
                eprintln!(
                    "The error is {} for the file {:?}, probably invalid password. Exiting.",
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
            break;
        }
        let blank: String = String::new();
        let write = fs::write(&filedata, &blank);
        if write.is_err() {
            eprintln!(
                "The error is {} for the file {:?}",
                write.unwrap_err(),
                &filedata
            );
            continue;
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
            continue;
        }
        if verbose {
            println!("The file {} has been decrypted successfully.", &filedata);
        }
    }
}
