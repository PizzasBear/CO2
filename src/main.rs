pub mod chacha;
pub(crate) mod common;
pub mod ecc;
pub mod rsa;
use num::BigInt;
use rand::prelude::*;
use rand::rngs::SmallRng;
use std::env;
use std::fs;

fn help() {
    println!(
        r#"CO2 by Max

co2 enc <algo>
    Encrypts a message.
co2 dec <algo>
    Decrypts a cipher text.
co2 sign <algo>
    Signs a message with a key.
co2 verify <algo>
    Verifies a signature on a message.
co2 gen <algo>
    Generates a key / keys for the algorithm.
co2 write <message>
    Writes the message to the file.
co2 read
    Read the message from the file.
co2 help
    Display this message.

available algorithms: rsa, Unimplemented[dsa, ecdsa, dh, ecdh]"#
    );
}

enum Algo {
    Rsa,
    Ecdsa,
}

fn algo_from_str(s: &str) -> Option<Algo> {
    match s {
        "rsa" => Some(Algo::Rsa),
        "ecdsa" => Some(Algo::Ecdsa),
        _ => None,
    }
}

fn get_pub_rsa_key() -> Result<rsa::PublicRsaKey, Box<dyn std::error::Error>> {
    match fs::read("./public-key") {
        Ok(bytes) => {
            let pub_key = bincode::deserialize(&bytes)?;
            Ok(pub_key)
        }
        Err(_) => {
            let sec_key: rsa::SecretRsaKey = bincode::deserialize(&fs::read("./secret-key")?)?;
            Ok(sec_key.pub_key())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SmallRng::from_entropy();
    let mut crng = StdRng::from_entropy();
    let mut hasher = blake3::Hasher::new();

    let args = env::args().collect::<Vec<_>>();
    // println!("{:?}", args);
    let mut arg_iter = args.iter();
    arg_iter.next();
    arg_iter.next().map_or_else(
        || {
            help();
            Result::<(), Box<dyn std::error::Error>>::Ok(())
        },
        |s| match (s.as_str(), arg_iter.next()) {
            ("enc", Some(s)) => algo_from_str(s).map_or_else(
                || {
                    println!("Unknown algorithm");
                    Ok(())
                },
                |algo| match algo {
                    Algo::Rsa => {
                        let pub_key = get_pub_rsa_key()?;
                        let m: String = bincode::deserialize(&fs::read("./message")?)?;
                        let m: BigInt =
                            BigInt::from_bytes_be(num::bigint::Sign::Plus, m.as_bytes());
                        fs::write(
                            "./cipher-text",
                            bincode::serialize(&pub_key.enc(&m).unwrap())?,
                        )?;
                        Ok(())
                    }
                    _ => {
                        println!("Unknown encryption algorithm");
                        Ok(())
                    }
                },
            ),
            ("dec", Some(s)) => algo_from_str(s).map_or_else(
                || {
                    println!("Unknown algorithm");
                    Ok(())
                },
                |algo| match algo {
                    Algo::Rsa => {
                        let sec_key: rsa::SecretRsaKey =
                            bincode::deserialize(&fs::read("./secret-key")?)?;
                        let c: BigInt = bincode::deserialize(&fs::read("./cipher-text")?)?;
                        fs::write(
                            "./message",
                            bincode::serialize(&String::from_utf8(
                                sec_key.dec(&c).unwrap().to_bytes_be().1,
                            )?)?,
                        )?;
                        Ok(())
                    }
                    _ => {
                        println!("Unknown decryption algorithm");
                        Ok(())
                    }
                },
            ),
            ("gen", Some(s)) => algo_from_str(s).map_or_else(
                || {
                    println!("Unknown algorithm");
                    Ok(())
                },
                |algo| match algo {
                    Algo::Rsa => {
                        let sec_key = rsa::gen_rsa_key(&mut rng, &mut crng);
                        fs::write("./secret-key", bincode::serialize(&sec_key)?)?;
                        fs::write("./public-key", bincode::serialize(&sec_key.pub_key())?)?;
                        Ok(())
                    }
                    Algo::Ecdsa => {
                        unimplemented!();
                        // fs::write("./secret-key", bincode::serialize(&sec_key)?)?;
                        // fs::write("./public-key", bincode::serialize(&sec_key.pub_key())?)?;
                        // Ok(())
                    }
                },
            ),
            ("sign", Some(s)) => algo_from_str(s).map_or_else(
                || {
                    println!("Unknown algorithm");
                    Ok(())
                },
                |algo| match algo {
                    Algo::Rsa => {
                        let sec_key: rsa::SecretRsaKey =
                            bincode::deserialize(&fs::read("./secret-key")?)?;
                        let m: String = bincode::deserialize(&fs::read("./message")?)?;
                        let m: BigInt =
                            BigInt::from_bytes_be(num::bigint::Sign::Plus, m.as_bytes());
                        fs::write(
                            "./signature",
                            bincode::serialize(&sec_key.sign(&mut hasher, &m).unwrap())?,
                        )?;
                        Ok(())
                    }
                    Algo::Ecdsa => {
                        unimplemented!();
                    }
                },
            ),
            ("verify", Some(s)) => algo_from_str(s).map_or_else(
                || {
                    println!("Unknown algorithm");
                    Ok(())
                },
                |algo| match algo {
                    Algo::Rsa => {
                        let pub_key = get_pub_rsa_key()?;
                        let m: String = bincode::deserialize(&fs::read("./message")?)?;
                        let m: BigInt =
                            BigInt::from_bytes_be(num::bigint::Sign::Plus, m.as_bytes());
                        let ds: BigInt = bincode::deserialize(&fs::read("./signature")?)?;
                        if pub_key.verify(&mut hasher, &m, &ds).unwrap() {
                            println!();
                            println!("Correct signature");
                        } else {
                            println!();
                            println!("Incorrect signature.");
                        }
                        Ok(())
                    }
                    Algo::Ecdsa => {
                        unimplemented!();
                    }
                },
            ),
            ("write", Some(s)) => {
                fs::write("./message", bincode::serialize(s)?)?;
                Ok(())
            }
            ("read", None) => {
                let m: String = bincode::deserialize(&fs::read("./message")?)?;
                println!("{}", m);
                Ok(())
            }
            ("help", None) => {
                help();
                Ok(())
            }
            _ => {
                println!("Unknown action.");
                Ok(())
            }
        },
    )?;
    Ok(())
}
