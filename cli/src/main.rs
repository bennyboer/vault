use std::error::Error;

use cmd_args::{arg, option, parser, Group};
use zeroize::Zeroize;

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
    .add_child(
        "open",
        Some(vec!["o"]),
        Group::new(
            Box::new(|args, options| {
                let retain_source = options.get("retain-source").unwrap().bool().unwrap();
                let source = args.get(0).unwrap().str().unwrap();

                run(Mode::Open, source, retain_source).unwrap();
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

                run(Mode::Close, source, retain_source).unwrap();
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

fn run(mode: Mode, source: &str, _retain_source: bool) -> Result<(), Box<dyn Error>> {
    // TODO check whether source is a file or a directory
    // TODO honor retain_source flag

    let mut password = rpassword::prompt_password("Password: ")?;

    match mode {
        Mode::Open => core::decrypt_file(
            source,
            &format!(
                "{}.opened",
                source.strip_suffix(".closed").unwrap_or(source).to_string()
            ),
            &password,
        ),
        Mode::Close => core::encrypt_file(
            source,
            &format!(
                "{}.closed",
                source.strip_suffix(".opened").unwrap_or(source).to_string()
            ),
            &password,
        ),
    }?;

    password.zeroize();

    Ok(())
}
