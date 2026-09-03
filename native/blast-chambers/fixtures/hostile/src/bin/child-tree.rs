use std::process::Command;

fn main() {
    let marker = std::env::var_os("BLAST_CHAMBERS_CHILD");
    if marker.is_none() {
        let mut child = Command::new(std::env::current_exe().expect("fixture path"))
            .env("BLAST_CHAMBERS_CHILD", "1")
            .spawn()
            .expect("spawn child");
        let _ = child.wait();
    } else {
        loop {
            std::thread::park();
        }
    }
}
