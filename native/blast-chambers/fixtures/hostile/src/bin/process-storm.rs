use std::process::Command;

fn main() {
    loop {
        let _ = Command::new(std::env::current_exe().expect("fixture path")).spawn();
    }
}
