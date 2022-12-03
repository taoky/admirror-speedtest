use std::{
    fs::File,
    io::{BufRead, BufReader},
    net,
    time::{Duration, Instant}, sync::{Arc, atomic::{AtomicBool, Ordering, AtomicU64}},
};

use clap::Parser;
use signal_hook::iterator::Signals;
use subprocess::ExitStatus;
use subprocess::{Exec, NullFile, Redirection};

#[derive(Parser, Debug)]
#[clap(about)]
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

macro_rules! checkpoint {
    ($term: expr, $tmp: expr) => {
        if $term.load(Ordering::Relaxed) {
            std::mem::drop($tmp);
            std::process::exit(1);
        }
    };
}

fn main() {
    let args = Args::parse();
    let log = File::create(args.log.unwrap_or_else(|| "/dev/null".to_string()))
        .expect("Cannot open rsync log file");
    // Handling SIGINT
    // Here we create a new thread to be the monitor
    let term = Arc::new(AtomicBool::new(false));
    let pid = Arc::new(AtomicU64::new(0));
    // signal_hook::flag::register_conditional_shutdown(libc::SIGINT, 1, Arc::clone(&term))
    //     .expect("Register conditional SIGINT signal handler failed");
    signal_hook::flag::register(libc::SIGINT, Arc::clone(&term))
        .expect("Register SIGINT signal handler failed");
    let mut sigint = Signals::new(&[libc::SIGINT]).expect("Register SIGINT signal handler failed");
    {
        let pid = pid.clone();
        std::thread::spawn(move || {
            for signal in sigint.forever() {
                match signal {
                    libc::SIGINT => {
                        println!("SIGINT received, killing rsync children...");
                        // TOUTOC.
                        // How to handle this trouble?
                        let pid = pid.load(Ordering::SeqCst);
                        if pid == 0 {
                            println!("No rsync process found");
                        } else {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGKILL);
                            }
                        }
                        std::thread::sleep(Duration::from_secs(5));
                        println!("Forcefully exiting...");
                        unsafe {
                            // If pid equals 0, then sig is sent to every process in the process group of the calling process.
                            libc::kill(0, libc::SIGKILL);
                        }
                        
                    }
                    _ => unreachable!(),
                }
            }
        });
    }
    // 1. read IP list from args.config
    let mut ips: Vec<Ip> = Vec::new();
    let config_path = args.config.unwrap_or_else(|| {
        let mut path = dirs::home_dir().expect("Get home dir path failed");
        path.push(".rsync-speedtest");
        path.to_str()
            .expect("Path is not a valid UTF-8 string")
            .to_string()
    });
    let ips_file = File::open(config_path).expect("Cannot open IP list file.");
    let iterator = BufReader::new(ips_file).lines();
    for line in iterator {
        let line = line.expect("Read IP list file failed");
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
            // create tmp file
            let tmp_file = create_tmp(&args.tmp_dir);
            checkpoint!(term, tmp_file);
            let time_start = Instant::now();
            let mut rsync_popen = Exec::cmd("rsync")
                .arg("-avP")
                .arg("--address")
                .arg(ip.ip.clone())
                .arg(args.upstream.clone())
                .arg(tmp_file.as_os_str().to_string_lossy().to_string())
                .stdin(NullFile)
                .stdout(log.try_clone().expect("Clone log file descriptor failed"))
                .stderr(Redirection::Merge)
                .popen()
                .expect("Failed to create rsync Popen object");
            pid.store(rsync_popen.pid().expect("Get rsync PID failed").into(), Ordering::SeqCst);
            let status = rsync_popen
                .wait_timeout(Duration::new(args.timeout as u64, 0))
                .expect("rsync timeout");
            checkpoint!(term, tmp_file);
            if status.is_none() {
                rsync_popen.kill().expect("rsync kill failed");
                rsync_popen.wait().expect("rsync wait failed");
            }
            pid.store(0, Ordering::SeqCst);
            let duration = time_start.elapsed();
            let mut duration_seconds = duration.as_secs_f64();
            if duration_seconds > args.timeout as f64 {
                duration_seconds = args.timeout as f64;
            }
            let state_str = match status {
                Some(status) => match status {
                    ExitStatus::Exited(0) => "✅ OK".to_owned(),
                    ExitStatus::Exited(code) => format!("❌ Exited with code {}", code),
                    ExitStatus::Signaled(signal) => format!("❌ Signaled with signal {}", signal),
                    ExitStatus::Other(code) => format!("❌ Other exit code {}", code),
                    ExitStatus::Undetermined => "❌ Unknown error".to_owned(),
                },
                None => "✅ Rsync timeout as expected".to_owned(),
            };
            // check file size
            let size = tmp_file
                .metadata()
                .expect("Get tmp file metadata failed")
                .len();
            println!("{}", size);
            let bandwidth = size as f64 / duration_seconds as f64; // Bytes / Seconds
            let bandwidth = bandwidth / 1024_f64; // KB/s
            println!(
                "{} ({}): {} KB/s ({})",
                ip.ip, ip.comment, bandwidth, state_str
            );
        }
    }
}
