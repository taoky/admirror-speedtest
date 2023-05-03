mod spawner;

use std::{
    cmp::min,
    fs::File,
    io::{BufRead, BufReader},
    net,
    process::{self, ExitStatus},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use clap::{clap_derive::ArgEnum, Parser};
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::spawner::{get_child, get_program_name};

#[derive(Debug, ArgEnum, Clone, Copy)]
pub enum Program {
    Rsync,
    Wget,
    Curl,
    Git,
}

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    /// Config file (IP list) path. Default to ~/.admirror-speedtest or (if not exist) ~/.rsync-speedtest
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

    /// Log file. Default to /dev/null
    #[clap(long)]
    log: Option<String>,

    /// Upstream path. Will be given to specified program
    #[clap(value_parser)]
    upstream: String,

    /// Program to use. It will try to detect by default (here curl will be used default for http(s))
    #[clap(long, arg_enum)]
    program: Option<Program>,
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

struct ProgramStatus {
    status: ExitStatus,
    time: Duration,
}

fn reap_all_children() {
    loop {
        unsafe {
            if libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) < 0 {
                break;
            }
        }
    }
}

fn kill_children(proc: &mut process::Child) -> ExitStatus {
    // Soundness requirement: the latest try_wait() should return Ok(None)
    // Elsewhere libc::kill may kill unrelated processes

    // rsync process model: we spawn "generator", and after receiving "file list"
    // generator spawns "receiver".
    // A race condition bug of rsync will cause receiver to hang for a long time
    // when both generator and receiver get SIGTERM/SIGINT/SIGHUP.
    // (See https://github.com/WayneD/rsync/issues/413 I posted)
    // So we seperate rsync from rsync-speedtest process group,
    // and just SIGTERM "generator" here, and let generator to SIGUSR1 receiver
    // and hoping that it will work
    // and well, I think that std::process::Child really should get a terminate() method!
    unsafe {
        libc::kill(proc.id() as i32, SIGTERM);
    }

    let res = proc.wait().expect("program wait() failed");
    // if receiver died before generator, the SIGCHLD handler of generator will help reap it
    // but we cannot rely on race condition to help do things right
    reap_all_children();

    res
}

fn wait_timeout(
    mut proc: process::Child,
    timeout: Duration,
    term: Arc<AtomicBool>,
) -> ProgramStatus {
    // Reference adaptable timeout algorithm from
    // https://github.com/hniksic/rust-subprocess/blob/5e89ac093f378bcfc03c69bdb1b4bcacf4313ce4/src/popen.rs#L778
    // Licensed under MIT & Apache-2.0

    let start = Instant::now();
    let deadline = start + timeout;

    let mut delay = Duration::from_millis(1);

    loop {
        let status = proc
            .try_wait()
            .expect("try waiting for rsync process failed");
        match status {
            Some(status) => {
                return ProgramStatus {
                    status,
                    time: start.elapsed(),
                }
            }
            None => {
                if term.load(Ordering::SeqCst) {
                    let time = start.elapsed();
                    let status = kill_children(&mut proc);
                    return ProgramStatus { status, time };
                }

                let now = Instant::now();
                if now >= deadline {
                    let time = start.elapsed();
                    let status = kill_children(&mut proc);
                    return ProgramStatus { status, time };
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
        .expect("Cannot open log file");
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&term)).expect("Register SIGINT handler failed");
    signal_hook::flag::register(SIGTERM, Arc::clone(&term))
        .expect("Register SIGTERM handler failed");

    // 1. read IP list from args.config
    let mut ips: Vec<Ip> = Vec::new();
    let config_path = args.config.clone().unwrap_or_else(|| {
        let mut path = dirs::home_dir().unwrap();
        path.push(".admirror-speedtest");
        path.to_str().unwrap().to_string()
    });
    let mut config_paths = vec![config_path];
    if args.config.is_none() {
        // Add .rsync-speedtest for backward compatibility
        let mut path = dirs::home_dir().unwrap();
        path.push(".rsync-speedtest");
        config_paths.push(path.to_str().unwrap().to_string());
    }

    let mut ips_file = None;
    for config in config_paths {
        if let Ok(file) = File::open(&config) {
            ips_file = Some(file);
            break;
        }
    }
    let ips_file = match ips_file {
        Some(ips_file) => ips_file,
        None => {
            panic!("Cannot open IP list file.")
        }
    };

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
    // 2. Detect which program should we run
    let program = match args.program {
        Some(program) => program,
        None => {
            // We need to detect by upstream

            // Though I don't think anyone will use ALL UPPERCASE here...
            let upstream = args.upstream.to_lowercase();
            if upstream.starts_with("rsync://") || upstream.contains("::") {
                Program::Rsync
            } else if upstream.starts_with("http://") || upstream.starts_with("https://") {
                if upstream.ends_with(".git") {
                    Program::Git
                } else {
                    Program::Curl
                }
            } else if upstream.starts_with("git://") {
                Program::Git
            } else {
                panic!("Cannot detect upstream program. Please specify with --program.")
            }
        }
    };
    // 3. run rsync for passes times and collect results
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
            let proc = get_child(&program, &ip.ip, &args.upstream, &tmp_file, &log);
            let rsync_status =
                wait_timeout(proc, Duration::from_secs(args.timeout as u64), term.clone());
            let status = rsync_status.status;
            let duration = rsync_status.time;
            let duration_seconds = duration.as_secs_f64();
            let mut state_str = {
                if duration_seconds > args.timeout as f64 {
                    format!("✅ {} timeout as expected", get_program_name(&program))
                } else {
                    match status.code() {
                        Some(code) => match code {
                            0 => "✅ OK".to_owned(),
                            _ => format!(
                                "❌ {} failed with code {}",
                                get_program_name(&program),
                                code
                            ),
                        },
                        None => format!("❌ {} killed by signal", get_program_name(&program)),
                    }
                }
            };
            if term.load(Ordering::SeqCst) {
                state_str += " (terminated by user)";
            }
            // check file size
            let size = tmp_file.metadata().unwrap().len();
            let bandwidth = size as f64 / duration_seconds; // Bytes / Seconds
            let bandwidth = bandwidth / 1024_f64; // KB/s
            println!(
                "{} ({}): {} KB/s ({})",
                ip.ip, ip.comment, bandwidth, state_str
            );
        }
    }
}
