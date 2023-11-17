FROM rust
RUN apt update && apt install libpcap-dev -y
COPY ./ ./
RUN cargo build --release
CMD ["./target/release/oxyflow"]
