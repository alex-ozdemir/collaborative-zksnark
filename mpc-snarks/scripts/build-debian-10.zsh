sudo apt install build-essential units git zsh ripgrep htop
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/alex-ozdemir/multiprover-snark.git
cd multiprover-snark/mpc-snark
cargo build --release --bin proof
