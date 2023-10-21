[![License](https://img.shields.io/github/license/DorianCoding/filecryption)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Github stars](https://img.shields.io/github/stars/DorianCoding/filecryption
)](https://github.com/DorianCoding/filecryption/stargazers)
[![Language](https://img.shields.io/badge/RUST-red)](https://github.com/rust-lang/rust)
# Filecryption
Allows encryption and decryption of files using Argon2 and XChaCha20Poly1305 in Rust.
## Usage
* Download binaries (in bin folder) or clone the repo and run `cargo run`. **Rust needs to be installed** (version >= 1.73)
* Enjoy :+1:
```
Allows encryption and decryption of files using Argon2 and XChaCha20Poly1305

Usage: filecryption [OPTIONS] <ACTION> [FILE]...

Arguments:
  <ACTION>   [possible values: encrypt, decrypt, compute]
  [FILE]...  File(s)/Directories to encrypt/decrypt

Options:
  -a, --argon2 <ARGON2>      Argon parameter (default should be fit, but can be computed with -t), set exponential for argon, must be between 5 (very low - low CPU devices) and 50 (nearly impossible to compute) [default: 15]
  -p, --password <PASSWORD>  Password input
  -r, --recursive            Recursive all directories and files
  -v, --verbose              verbose mode
  -h, --help                 Print help
  -V, --version              Print version

```


> [!IMPORTANT]
> Do not try to reencrypt already encrypted files and do not alter the hidden parameters file created once encrypted.
> Do not attempt to change extension of files.


Example :
* `./script encrypt file.txt` to encrypt file.txt
* `./script decrypt file.txt` to decrypt file.txt
* `./script encrypt -rv ~` to encrypt and verbose full home
* `./script encrypt -rv ~` to decrypt and verbose full home

## Informations

Directory won't be taken into account unless recursive is set. 
Password would be asked in secure tty but can be unsecurely provide as an argument.
A hidden file is created containing the salt and derivation parameters for Argon2.
It should be automatically detected when encrypting and decrypting. **This file is needed to decrypt**.

## Argon infos

Depending on your platform and devices, [argon parameters](https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs) can be edited. To detect the trade-off configuration, run `./script compute`
and provide this value as `-a value` when using this script. The default value is 16 and is [the recommended value](https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice). 

<details>
  <summary>Table of values for argon and memory cost</summary>

| Value of argon | Memory cost |
| --- | --- |
| 5 | 32 Kib |
| 6 | 64 Kib |
| 7 | 128 Kib |
| 8 | 256 Kib |
| 9 | 512 Kib |
| 10 | 1.02 Mib |
| 11 | 2.05 Mib |
| 12 | 4.1 Mib |
| 13 | 8.19 Mib |
| 14 | 16.4 Mib |
| 15 | 32.8 Mib |
| Recommended --> 16 | 65.5 Mib |
| 17 | 131 Mib |
| 18 | 262 Mib |
| 19 | 524 Mib |
| 20 | 1.05 Gib |
| 21 | 2.1 Gib |
| 22 | 4.19 Gib |
| 23 | 8.39 Gib |
| 24 | 16.8 Gib |
| 25 | 33.6 Gib |
| 26 | 67.1 Gib |
| 27 | 134 Gib |
| 28 | 268 Gib |
| 29 | 537 Gib |
| 30 | 1.07 Tib |
| 31 | 2.15 Tib |
| 32 | 4.29 Tib |
| 33 | 8.59 Tib |
| 34 | 17.2 Tib |
| 35 | 34.4 Tib |
| 36 | 68.7 Tib |
| 37 | 137 Tib |
| 38 | 275 Tib |
| 39 | 550 Tib |
| 40 | 1.1 Pib |
| 41 | 2.2 Pib |
| 42 | 4.4 Pib |
| 43 | 8.8 Pib |
| 44 | 17.6 Pib |
| 45 | 35.2 Pib |
| 46 | 70.4 Pib |
| 47 | 141 Pib |
| 48 | 281 Pib |
| 49 | 563 Pib |
| 50 | 1.13 Eib |

</details>
