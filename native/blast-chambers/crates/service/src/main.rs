#![deny(unsafe_op_in_unsafe_fn)]

fn main() {
    // Installation is intentionally separate from compilation. Until the
    // privileged acceptance suite provisions the SCM identity, invoking this
    // binary cannot accidentally create a weaker console-mode broker.
    eprintln!(
        "blast-chambers-service: backend_unavailable: install via the protected service installer"
    );
    std::process::exit(78);
}
