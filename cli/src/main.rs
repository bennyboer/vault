use std::env;
use std::error::Error;

use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        panic!("Usage: ./vault [open/close] <file_path>");
    }

    let mode = &args[1][..];
    let file_path = &args[2][..];
    let mut password = rpassword::prompt_password("Password: ")?;

    match mode {
        "open" => core::decrypt_file(
            file_path,
            &format!(
                "{}.opened",
                file_path
                    .strip_suffix(".closed")
                    .unwrap_or(file_path)
                    .to_string()
            ),
            &password,
        ),
        "close" => core::encrypt_file(
            file_path,
            &format!(
                "{}.closed",
                file_path
                    .strip_suffix(".opened")
                    .unwrap_or(file_path)
                    .to_string()
            ),
            &password,
        ),
        _ => panic!("Either specify 'open' or 'close' as the first argument"),
    }?;

    password.zeroize();

    Ok(())
}
