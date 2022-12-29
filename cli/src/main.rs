use std::error::Error;

use cmd_args::{arg, option, parser, Group};
use zeroize::Zeroize;

#[derive(Copy, Clone)]
enum Mode {
    Open,
    Close,
}

fn main() -> Result<(), Box<dyn Error>> {
    let group = Group::new(
        Box::new(|_args, _options| {
            println!("Check vault --help for usage information");
        }),
        "Vault CLI",
    )
    .add_option(
        option::Descriptor::new(
            "retain-source",
            option::Type::Bool { default: false },
            "Whether to retain the source file(s) after encryption/decryption",
        )
        .add_alias("r"),
    )
    .add_option(
        option::Descriptor::new(
            "password",
            option::Type::Str {
                default: String::new(),
            },
            "The password to use for encryption/decryption",
        )
        .add_alias("p"),
    )
    .add_child(
        "open",
        Some(vec!["o"]),
        Group::new(
            Box::new(|args, options| {
                let retain_source = options.get("retain-source").unwrap().bool().unwrap();
                let source = args.get(0).unwrap().str().unwrap();
                let password = options
                    .get("password")
                    .unwrap()
                    .str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                if let Err(e) = run(Mode::Open, source, retain_source, password) {
                    println!("Failed to decrypt: {}", e);
                }
            }),
            "Open the vault (Decrypting file(s))",
        )
        .add_argument(arg::Descriptor::new(
            arg::Type::Str,
            "A file or a directory to decrypt all files recursively in",
        )),
    )
    .add_child(
        "close",
        Some(vec!["c"]),
        Group::new(
            Box::new(|args, options| {
                let retain_source = options.get("retain-source").unwrap().bool().unwrap();
                let source = args.get(0).unwrap().str().unwrap();
                let password = options
                    .get("password")
                    .unwrap()
                    .str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                if let Err(e) = run(Mode::Close, source, retain_source, password) {
                    println!("Failed to encrypt: {}", e);
                }
            }),
            "Close the vault (Encrypting file(s))",
        )
        .add_argument(arg::Descriptor::new(
            arg::Type::Str,
            "A file or a directory to encrypt all files recursively in",
        )),
    );

    parser::parse(group, None)?;

    Ok(())
}

fn run(
    mode: Mode,
    source: &str,
    retain_source: bool,
    password: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let mut password = password
        .map(|p| Ok(p))
        .unwrap_or_else(|| rpassword::prompt_password("Password: "))?;

    let meta_data = std::fs::metadata(source)?;
    if meta_data.is_file() {
        run_for_file(mode, source, &password, retain_source)?;
    } else {
        run_for_directory(mode, source, &password, retain_source)?;
    }

    password.zeroize();

    Ok(())
}

fn run_for_directory(
    mode: Mode,
    source: &str,
    password: &str,
    retain_source: bool,
) -> Result<(), Box<dyn Error>> {
    let entries = std::fs::read_dir(source)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_str().unwrap();

        let meta_data = entry.metadata()?;
        if meta_data.is_file() {
            run_for_file(mode, path_str, &password, retain_source)?;
        } else {
            run_for_directory(mode, path_str, &password, retain_source)?;
        }
    }

    Ok(())
}

fn run_for_file(
    mode: Mode,
    source: &str,
    password: &str,
    retain_source: bool,
) -> Result<(), Box<dyn Error>> {
    let target_path = match mode {
        Mode::Open => source.strip_suffix(".closed").unwrap_or(source).to_string(),
        Mode::Close => format!("{}.closed", source),
    };

    if let Err(e) = match mode {
        Mode::Open => vault_core::decrypt_file(source, &target_path, &password),
        Mode::Close => vault_core::encrypt_file(source, &target_path, &password),
    } {
        std::fs::remove_file(target_path)?;
        return Err(e);
    }

    let delete_source = !retain_source;
    if delete_source {
        std::fs::remove_file(source)?;
    }

    Ok(())
}
