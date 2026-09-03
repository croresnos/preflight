#![forbid(unsafe_code)]

use blast_chambers_protocol::{DoctorResponse, PROTOCOL_VERSION, ResourceControls};

fn unavailable() -> DoctorResponse {
    DoctorResponse {
        service_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: PROTOCOL_VERSION,
        service_pid: 0,
        identity_verified: false,
        controls: ResourceControls {
            suspended_before_assignment: false,
            kill_on_job_close: false,
            active_process_limit: false,
            process_memory_limit: false,
            job_memory_limit: false,
            cpu_hard_cap: false,
            cpu_time_limit: false,
            wall_clock_limit: false,
            output_limit: false,
            no_breakaway: false,
            caller_token: false,
        },
        missing_protections: vec![
            "filesystem".into(),
            "registry".into(),
            "credentials".into(),
            "network".into(),
            "ui_devices".into(),
            "same_user_brokers".into(),
        ],
        reason_code: "backend_unavailable".into(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["doctor", "--json"] {
        println!(
            "{}",
            serde_json::to_string(&unavailable()).expect("serializable response")
        );
        return;
    }
    eprintln!(
        "blast-chambers-client: backend_unavailable: the authenticated SCM pipe is not installed"
    );
    std::process::exit(78);
}
