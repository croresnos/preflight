use std::io::{self, Write};

fn main() {
    let block = [b'X'; 8192];
    let mut stdout = io::stdout().lock();
    loop {
        if stdout.write_all(&block).is_err() {
            break;
        }
    }
}
