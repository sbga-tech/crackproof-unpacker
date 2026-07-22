mod cli;

use std::process;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("{}", cli::failure_line(&error));
        process::exit(1);
    }
}
