use std::{
    fs::File,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::Program;

#[inline]
pub fn get_program_name(program: &Program) -> String {
    match program {
        Program::Rsync => "rsync",
        Program::Wget => "wget",
        Program::Curl => "curl",
        Program::Git => "git",
    }
    .to_owned()
}

pub fn get_child(
    program: &Program,
    bind_ip: &str,
    upstream: &str,
    tmp_path: &Path,
    log_file: &File,
) -> Child {
    let mut cmd: Command;
    match program {
        Program::Rsync => {
            cmd = std::process::Command::new("rsync");
            cmd.arg("-avP")
                .arg("--inplace")
                .arg("--address")
                .arg(bind_ip)
                .arg(upstream)
                .arg(tmp_path.as_os_str().to_string_lossy().to_string())
        }
        Program::Curl => {
            cmd = std::process::Command::new("curl");
            cmd.arg("-o")
                .arg(tmp_path.as_os_str().to_string_lossy().to_string())
                .arg("--interface")
                .arg(bind_ip)
                .arg(upstream)
        }
        Program::Wget => {
            cmd = std::process::Command::new("wget");
            cmd.arg("-O")
                .arg(tmp_path.as_os_str().to_string_lossy().to_string())
                .arg("--bind-address")
                .arg(bind_ip)
                .arg(upstream)
        }
        Program::Git => unimplemented!("Git is not supported yet."),
    }
    .stdin(Stdio::null())
    .stdout(Stdio::from(
        log_file
            .try_clone()
            .expect("Clone log file descriptor failed (stdout)"),
    ))
    .stderr(Stdio::from(
        log_file
            .try_clone()
            .expect("Clone log file descriptor failed (stderr)"),
    ))
    .process_group(0) // Don't receive SIGINT from tty: we handle it ourselves (for rsync)
    .spawn()
    .unwrap_or_else(|_| {
        panic!(
            "Failed to spawn {} with timeout.",
            get_program_name(program)
        )
    })
}
