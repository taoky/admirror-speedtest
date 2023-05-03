// An equivalent C implementation I wrote before:
// https://github.com/ustclug/ustcmirror-images/blob/7eab38bceeaa5a6842c626c1674fcc866f869216/yum-sync/binder.c

#[macro_use]
extern crate lazy_static;

use std::{env, fs::File, io::Read, mem, sync::Mutex};

use ctor::ctor;
use redhook::{hook, real};

lazy_static! {
    static ref IPV6: Mutex<bool> = Mutex::new(false);
    static ref BIND: Mutex<String> = Mutex::new("".to_owned());
    // IPs in ALLOWLIST will not be handled by bind() in connect()
    static ref ALLOWLIST: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

extern "C" {
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
    fn inet_ntop(af: libc::c_int, src: *const libc::c_void, dst: *mut libc::c_char, size: libc::socklen_t) -> *const libc::c_char;
}

#[ctor]
fn init() {
    let bind_addr = match env::var("BIND_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("BIND_ADDRESS not set, exiting");
            std::process::exit(1);
        }
    };
    if bind_addr.contains(':') {
        *IPV6.lock().unwrap() = true;
    }
    *BIND.lock().unwrap() = bind_addr;

    // Parse resolv.conf if possible, to avoid issues under IPv6
    let mut buf = Vec::with_capacity(4096);
    let f = File::open("/etc/resolv.conf")
        .and_then(|mut f| f.read_to_end(&mut buf))
        .and_then(|_| {
            resolv_conf::Config::parse(&buf)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
        });
    if let Ok(conf) = f {
        let mut allowlist = ALLOWLIST.lock().unwrap();
        for nameserver in conf.nameservers {
            allowlist.push(nameserver.to_string());
        }
    } else {
        eprintln!("warn: failed to parse /etc/resolv.conf");
    }
}

hook! {
    unsafe fn bind(
        sockfd: i32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t
    ) -> i32 => my_bind {
        // Do nothing if sa_family is neither AF_INET or AF_INET6
        let sa_family = (*addr).sa_family as i32;
        if sa_family != libc::AF_INET && sa_family != libc::AF_INET6 {
            return real!(bind)(sockfd, addr, addrlen);
        }
        // If getsockopt() failed, don't go further
        let mut optval: libc::c_int = 0;
        let mut optlen: libc::socklen_t = mem::size_of::<libc::c_int>() as _;
        if libc::getsockopt(sockfd, libc::SOL_SOCKET, libc::SO_TYPE, &mut optval as *mut _ as *mut _, &mut optlen as *mut _) != 0 {
            return real!(bind)(sockfd, addr, addrlen);
        }
        // We only want to handle TCP sockets
        if optval != libc::SOCK_STREAM {
            return real!(bind)(sockfd, addr, addrlen);
        }

        let ipv6 = {
            let v6 = IPV6.lock().unwrap();
            *v6
        };
        let bind_addr = {
            let addr = BIND.lock().unwrap();
            addr.clone()
        };
        match ipv6 {
            true => {
                let mut addr6: libc::sockaddr_in6 = mem::zeroed();
                addr6.sin6_family = libc::AF_INET6 as _;
                inet_pton(libc::AF_INET6, bind_addr.as_ptr() as *const _, &mut addr6.sin6_addr as *mut _ as *mut _);
                real!(bind)(sockfd, &addr6 as *const _ as *const _, mem::size_of::<libc::sockaddr_in6>() as _)
            }
            false => {
                let mut addr4: libc::sockaddr_in = mem::zeroed();
                addr4.sin_family = libc::AF_INET as _;
                inet_pton(libc::AF_INET, bind_addr.as_ptr() as *const _, &mut addr4.sin_addr as *mut _ as *mut _);
                real!(bind)(sockfd, &addr4 as *const _ as *const _, mem::size_of::<libc::sockaddr_in>() as _)
            }
        }
    }
}

hook! {
    unsafe fn connect(
        sockfd: i32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t
    ) -> i32 => my_connect {
        let sa_family = (*addr).sa_family as i32;
        if sa_family != libc::AF_INET && sa_family != libc::AF_INET6 {
            real!(connect)(sockfd, addr, addrlen)
        } else {
            let ipv6 = {
                let v6 = IPV6.lock().unwrap();
                *v6
            };
            if (sa_family == libc::AF_INET && ipv6) || (sa_family == libc::AF_INET6 && !ipv6) {
                // casting to sockaddr_in or sockaddr_in6
                let data = match sa_family {
                    libc::AF_INET => {
                        let addr4: &libc::sockaddr_in = &*(addr as *const _ as *const _);
                        &addr4.sin_addr as *const _ as *const _
                    }
                    libc::AF_INET6 => {
                        let addr6: &libc::sockaddr_in6 = &*(addr as *const _ as *const _);
                        &addr6.sin6_addr as *const _ as *const _
                    }
                    _ => unreachable!()
                };
                // get addr string
                let mut addr_str = [0u8; 128];
                let addr_str_ptr = addr_str.as_mut_ptr() as *mut libc::c_char;
                let addr_str_len = addr_str.len() as libc::socklen_t;
                let res = inet_ntop(sa_family, data, addr_str_ptr, addr_str_len);
                if res.is_null() {
                    // TODO: errno
                    return -1;
                }
                let ip_str = std::ffi::CStr::from_ptr(addr_str_ptr).to_str().unwrap();
                // eprintln!("connecting to {}", ip_str);
                for allow_ip in ALLOWLIST.lock().unwrap().iter() {
                    if ip_str.starts_with(allow_ip) {
                        return real!(connect)(sockfd, addr, addrlen);
                    }
                }
                return -1;
            }
            my_bind(sockfd, addr, 0);
            real!(connect)(sockfd, addr, addrlen)
        }
    }
}
