use std::{
    cmp::min,
    fs::File,
    io::{BufRead, BufReader},
    net,
    process::{self, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use clap::Parser;
use libc::SIGKILL;
use signal_hook::consts::{SIGINT, SIGTERM};

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    /// Config file (IP list) path. Default to ~/.rsync-speedtest
    #[clap(short, long)]
    config: Option<String>,

    /// Passes number
    #[clap(short, long, default_value = "3")]
    pass: usize,

    /// Timeout (seconds)
    #[clap(short, long, default_value = "30")]
    timeout: usize,

    /// Tmp file path. Default to env::temp_dir() (/tmp in Linux system)
    #[clap(long)]
    tmp_dir: Option<String>,

    /// Rsync log file. Default to /dev/null
    #[clap(long)]
    log: Option<String>,

    /// Upstream path. Will be given to rsync
    #[clap(value_parser)]
    upstream: String,
}

struct Ip {
    ip: String,
    comment: String,
}

fn create_tmp(tmp_dir: &Option<String>) -> mktemp::Temp {
    match tmp_dir {
        Some(tmp_dir) => mktemp::Temp::new_file_in(tmp_dir),
        None => mktemp::Temp::new_file(),
    }
    .expect("tmp file created failed")
}

struct RsyncStatus {
    status: ExitStatus,
    time: Duration,
}

fn kill_rsync_group(proc: &mut process::Child, sigterm: bool) -> ExitStatus {
    // Soundness requirement: the latest try_wait() should return Ok(None)
    // Elsewhere libc::kill may kill unrelated processes
    if sigterm {
        // Assuming that rsync can handle its child processes
        unsafe {
            libc::kill(proc.id() as i32, SIGTERM);
        }
    }

    // wait for 5 secs, see if it's dead
    let start = Instant::now();
    let delay = Duration::from_millis(100);
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(status)) = proc.try_wait() {
            // here we believe that rsync has handled its child processes
            return status;
        }
        std::thread::sleep(delay);
    }
    // Sorry, it's still alive, kill them all
    println!("Forcefully killing rsync process (5 sec timeout), the result maybe incorrect.");
    unsafe {
        libc::killpg(proc.id() as i32, SIGKILL);
    }
    let status = proc.wait().expect("wait failed");

    // reap all children
    loop {
        unsafe {
            if libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) < 0 {
                break;
            }
        }
    }

    status
}

fn wait_timeout(mut proc: process::Child, timeout: Duration, term: Arc<AtomicBool>) -> RsyncStatus {
    // Reference adaptable timeout algorithm from
    // https://github.com/hniksic/rust-subprocess/blob/5e89ac093f378bcfc03c69bdb1b4bcacf4313ce4/src/popen.rs#L778
    // Licnesed under MIT & Apache-2.0

    let start = Instant::now();
    let deadline = start + timeout;

    let mut delay = Duration::from_millis(1);

    loop {
        let status = proc
            .try_wait()
            .expect("try waiting for rsync process failed");
        match status {
            Some(status) => {
                return RsyncStatus {
                    status,
                    time: start.elapsed(),
                }
            }
            None => {
                if term.load(Ordering::SeqCst) {
                    // When user press Ctrl + C, rsync process will also receive SIGINT
                    // So we should not send SIGTERM again
                    let time = start.elapsed();
                    let status = kill_rsync_group(&mut proc, false);
                    return RsyncStatus { status, time };
                }

                let now = Instant::now();
                if now >= deadline {
                    let time = start.elapsed();
                    let status = kill_rsync_group(&mut proc, true);
                    return RsyncStatus { status, time };
                }

                let remaining = deadline.duration_since(now);
                std::thread::sleep(min(delay, remaining));
                delay = min(delay * 2, Duration::from_millis(100));
            }
        }
    }
}

fn main() {
    let args = Args::parse();
    let log = File::create(args.log.unwrap_or_else(|| "/dev/null".to_string()))
        .expect("Cannot open rsync log file");
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&term)).expect("Register SIGINT handler failed");
    signal_hook::flag::register(SIGTERM, Arc::clone(&term))
        .expect("Register SIGTERM handler failed");
    // 1. read IP list from args.config
    let mut ips: Vec<Ip> = Vec::new();
    let config_path = args.config.unwrap_or_else(|| {
        let mut path = dirs::home_dir().unwrap();
        path.push(".rsync-speedtest");
        path.to_str().unwrap().to_string()
    });
    let ips_file = File::open(config_path).expect("Cannot open IP list file.");
    let iterator = BufReader::new(ips_file).lines();
    for line in iterator {
        let line = line.unwrap();
        let line: Vec<&str> = line.split(' ').collect();
        assert!(line.len() <= 2);
        let ip = line[0];
        // sanity check: is IP valid?
        let _ = ip.parse::<net::IpAddr>().expect("Invalid IP address");
        let comment = if line.len() == 2 { line[1] } else { "" };
        ips.push(Ip {
            ip: ip.to_string(),
            comment: comment.to_string(),
        });
    }
    // 2. run rsync for passes times and collect results
    for pass in 0..args.pass {
        println!("Pass {}:", pass);
        for ip in &ips {
            if term.load(Ordering::SeqCst) {
                println!("Terminated by user.");
                // return instead of directly exit() so we can clean up tmp files
                return;
            }
            // create tmp file
            let tmp_file = create_tmp(&args.tmp_dir);
            let proc = std::process::Command::new("rsync")
                .arg("-avP")
                .arg("--address")
                .arg(ip.ip.clone())
                .arg(args.upstream.clone())
                .arg(tmp_file.as_os_str().to_string_lossy().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::from(
                    log.try_clone()
                        .expect("Clone log file descriptor failed (stdout)"),
                ))
                .stderr(Stdio::from(
                    log.try_clone()
                        .expect("Clone log file descriptor failed (stderr)"),
                ))
                .spawn()
                .expect("Failed to spawn rsync with timeout.");
            let rsync_status =
                wait_timeout(proc, Duration::from_secs(args.timeout as u64), term.clone());
            let status = rsync_status.status;
            let duration = rsync_status.time;
            let duration_seconds = duration.as_secs_f64();
            let mut state_str = {
                if duration_seconds > args.timeout as f64 {
                    "✅ Rsync timeout as expected".to_owned()
                } else {
                    match status.code() {
                        Some(code) => match code {
                            0 => "✅ OK".to_owned(),
                            _ => format!("❌ Rsync failed with code {}", code),
                        },
                        None => "❌ Rsync killed by signal".to_owned(),
                    }
                }
            };
            if term.load(Ordering::SeqCst) {
                state_str += " (terminated by user)";
            }
            // check file size
            let size = tmp_file.metadata().unwrap().len();
            let bandwidth = size as f64 / duration_seconds as f64; // Bytes / Seconds
            let bandwidth = bandwidth / 1024_f64; // KB/s
            println!(
                "{} ({}): {} KB/s ({})",
                ip.ip, ip.comment, bandwidth, state_str
            );
        }
    }
}
