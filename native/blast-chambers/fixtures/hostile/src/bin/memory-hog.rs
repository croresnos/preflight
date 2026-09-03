fn main() {
    let mut allocations = Vec::new();
    loop {
        allocations.push(vec![0xA5_u8; 1024 * 1024]);
    }
}
