FROM centos:7 AS builder
# RUN yum install -y epel-release
RUN yum install -y gcc gcc-c++ make cmake3 openssl-devel libpcap-devel
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
COPY ./ /app
RUN cargo build --release

FROM scratch as export-stage
COPY --from=builder /app/target/release/oxyflow oxyflow
