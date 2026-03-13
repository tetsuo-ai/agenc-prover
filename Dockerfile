FROM rust:1.90-bookworm AS build
ARG RZUP_VERSION=0.5.1
ARG RISC0_RUST_VERSION=1.91.1
ARG RISC0_CPP_VERSION=2024.01.05
ARG RISC0_VERSION=3.0.5
ARG RISC0_GROTH16_VERSION=0.1.0
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"
RUN cargo install --locked --version ${RZUP_VERSION} rzup \
  && rzup install rust ${RISC0_RUST_VERSION} \
  && rzup install cpp ${RISC0_CPP_VERSION} \
  && rzup install cargo-risczero ${RISC0_VERSION} \
  && rzup install r0vm ${RISC0_VERSION} \
  && rzup install risc0-groth16 ${RISC0_GROTH16_VERSION}
WORKDIR /app
COPY . .
RUN cargo build --release -p agenc-prover-server --features production-prover

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/agenc-prover-server /usr/local/bin/agenc-prover-server
ENV PROVER_HOST=0.0.0.0
ENV PROVER_PORT=8787
EXPOSE 8787
CMD ["agenc-prover-server"]
