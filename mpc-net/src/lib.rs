use lazy_static::lazy_static;
use log::debug;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

#[macro_use]
lazy_static! {
    pub static ref CH: Mutex<FieldChannel> = Mutex::new(FieldChannel::default());
}

/// Macro for locking the FieldChannel singleton in the current scope.
macro_rules! get_ch {
    () => {
        CH.lock().expect("Poisoned FieldChannel")
    };
}

pub struct FieldChannel {
    /// Empty if unitialized
    pub stream: Option<TcpStream>,
    pub self_addr: SocketAddr,
    pub other_addr: SocketAddr,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub exchanges: usize,
    pub talk_first: bool,
}

impl std::default::Default for FieldChannel {
    #[inline]
    fn default() -> Self {
        Self {
            stream: None,
            self_addr: "127.0.0.1:8000".parse().unwrap(),
            other_addr: "127.0.0.1:8000".parse().unwrap(),
            bytes_sent: 0,
            bytes_recv: 0,
            exchanges: 0,
            talk_first: false,
        }
    }
}

impl FieldChannel {
    #[inline]
    pub fn connect<A1: ToSocketAddrs, A2: ToSocketAddrs>(
        &mut self,
        self_addr: A1,
        other_addr: A2,
        talk_first: bool,
    ) {
        self.self_addr = self_addr.to_socket_addrs().unwrap().next().unwrap();
        self.other_addr = other_addr.to_socket_addrs().unwrap().next().unwrap();
        self.talk_first = talk_first;
        debug!("I am {}, connecting to {}", self.self_addr, self.other_addr);
        self.stream = Some(if talk_first {
            debug!("Attempting to contact peer");
            loop {
                let mut ms_waited = 0;
                match TcpStream::connect(self.other_addr) {
                    Ok(s) => break s,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::ConnectionRefused {
                            ms_waited += 100;
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            if ms_waited % 3_000 == 0 {
                                debug!("Still waiting");
                            } else if ms_waited > 30_000 {
                                panic!("Could not find peer in 30s");
                            }
                        } else {
                            panic!("Error during FieldChannel::new: {}", e);
                        }
                    }
                }
            }
        } else {
            let listener = TcpListener::bind(self.self_addr).unwrap();
            debug!("Waiting for peer to contact us");
            let (stream, _addr) = listener.accept().unwrap();
            stream
        });
        // disable nagle's alg
        self.stream.as_mut().unwrap().set_nodelay(true).unwrap();
        self.stream.as_mut().unwrap().set_nonblocking(true).unwrap();
    }
    #[inline]
    pub fn stream(&mut self) -> &mut TcpStream {
        self.stream
            .as_mut()
            .expect("Unitialized FieldChannel. Did you forget init(..)?")
    }

    #[inline]
    pub fn send_slice(&mut self, v: &[u8]) {
        let s = self.stream();
        let bytes = (v.len() as u64).to_ne_bytes();
        s.write_all(&bytes[..]).unwrap();
        s.write_all(v).unwrap();
        self.bytes_sent += bytes.len() + v.len();
    }

    #[inline]
    pub fn recv_vec(&mut self) -> Vec<u8> {
        let s = self.stream();
        let mut len = [0u8; 8];
        s.read_exact(&mut len[..]).unwrap();
        let mut bytes = vec![0u8; u64::from_ne_bytes(len) as usize];
        s.read_exact(&mut bytes[..]).unwrap();
        self.bytes_recv += bytes.len() + len.len();
        bytes
    }

    #[inline]
    pub fn exchange_bytes(&mut self, bytes_out: &[u8]) -> std::io::Result<Vec<u8>> {
        let s = self.stream();
        let n = bytes_out.len();
        let mut bytes_in = vec![0u8; n];
        let mut bytes_in_offset = 0;
        let mut bytes_out_offset = 0;
        while bytes_out_offset < n || bytes_in_offset < n {
            if bytes_out_offset < n {
                match s.write(&bytes_out[bytes_out_offset..]) {
                    Ok(written) => {
                        bytes_out_offset += written;
                        let _e = s.flush();
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                        } else if e.kind() == std::io::ErrorKind::Interrupted {
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            if bytes_in_offset < n {
                match s.read(&mut bytes_in[bytes_in_offset..]) {
                    Ok(read) => {
                        bytes_in_offset += read;
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                        } else if e.kind() == std::io::ErrorKind::Interrupted {
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }
        self.exchanges += 1;
        self.bytes_sent += n;
        self.bytes_recv += n;
        Ok(bytes_in)
    }

    #[inline]
    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            bytes_recv: self.bytes_recv,
            bytes_sent: self.bytes_sent,
            exchanges: self.exchanges,
        }
    }

    #[inline]
    pub fn reset_stats(&mut self) {
        self.bytes_recv = 0;
        self.bytes_sent = 0;
        self.exchanges = 0;
    }
}

#[inline]
/// Initialize the MPC
pub fn init<A1: ToSocketAddrs, A2: ToSocketAddrs>(self_: A1, peer: A2, talk_first: bool) {
    let mut ch = get_ch!();
    assert!(
        ch.stream.is_none(),
        "FieldChannel should no be re-intialized. Did you call init(..) twice?"
    );
    ch.connect(self_, peer, talk_first);
}

#[inline]
pub fn deinit() {
    CH.lock().expect("Poisoned FieldChannel").stream = None;
}

#[derive(Debug)]
pub struct ChannelStats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub exchanges: usize,
}

#[inline]
pub fn exchange_bytes(bytes_out: &[u8]) -> std::io::Result<Vec<u8>> {
    CH.lock().expect("Poisoned FieldChannel").exchange_bytes(bytes_out)
}

#[inline]
pub fn stats() -> ChannelStats {
    CH.lock().expect("Poisoned FieldChannel").stats()
}

#[inline]
pub fn reset_stats() {
    CH.lock().expect("Poisoned FieldChannel").reset_stats()
}

/// Are you the first party in the MPC?
#[inline]
pub fn am_first() -> bool {
    get_ch!().talk_first
}
