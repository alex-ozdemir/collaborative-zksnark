pub mod multi;
pub mod two;

pub use two::MpcTwoNet;
pub use multi::MpcMultiNet;

#[derive(Clone, Debug)]
pub struct Stats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub broadcasts: usize,
    pub to_king: usize,
    pub from_king: usize,
}

impl std::default::Default for Stats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_recv: 0,
            broadcasts: 0,
            to_king: 0,
            from_king: 0,
        }
    }
}

pub trait MpcNet {
    /// Am I the first party?
    #[inline]
    fn am_king() -> bool {
        Self::party_id() == 0
    }
    /// How many parties are there?
    fn n_parties() -> usize;
    /// What is my party number (0 to n-1)?
    fn party_id() -> usize;
    /// Initialize the network layer from a file.
    /// The file should contain one HOST:PORT setting per line, corresponding to the addresses of
    /// the parties in increasing order.
    ///
    /// Parties are zero-indexed.
    fn init_from_file(path: &str, party_id: usize);
    /// Is the network layer initalized?
    fn is_init() -> bool;
    /// Uninitialize the network layer, closing all connections.
    fn deinit();
    /// Set statistics to zero.
    fn reset_stats();
    /// Get statistics.
    fn stats() -> Stats;
    /// All parties send bytes to each other.
    fn broadcast_bytes(bytes: &[u8]) -> Vec<Vec<u8>>;
    /// All parties send bytes to the king.
    fn send_bytes_to_king(bytes: &[u8]) -> Option<Vec<Vec<u8>>>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    fn recv_bytes_from_king(bytes: Option<Vec<Vec<u8>>>) -> Vec<u8>;

    /// Everyone sends bytes to the king, who recieves those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.
    #[inline]
    fn king_compute(bytes: &[u8], f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
        let king_response = Self::send_bytes_to_king(bytes).map(f);
        Self::recv_bytes_from_king(king_response)
    }
}
