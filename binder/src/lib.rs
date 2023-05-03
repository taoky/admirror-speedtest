// An equivalent C implementation I wrote before:
// https://github.com/ustclug/ustcmirror-images/blob/7eab38bceeaa5a6842c626c1674fcc866f869216/yum-sync/binder.c

#[macro_use]
extern crate lazy_static;

use std::{env, mem, sync::Mutex};

use ctor::ctor;
use redhook::{hook, real};

lazy_static! {
    static ref IPV6: Mutex<bool> = Mutex::new(false);
    static ref BIND: Mutex<String> = Mutex::new("".to_owned());
}

extern "C" {
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
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
            my_bind(sockfd, addr, 0);
            real!(connect)(sockfd, addr, addrlen)
        }
    }
}
