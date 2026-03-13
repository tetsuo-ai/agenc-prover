FROM rust:1.90-bookworm AS build
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"
WORKDIR /app
COPY . .
COPY scripts/production-toolchain.env ./production-toolchain.env
RUN set -eu \
  && . ./production-toolchain.env \
  && cargo install --locked --version "${RZUP_VERSION}" rzup \
  && rzup install rust "${RISC0_RUST_VERSION}" \
  && rzup install cpp "${RISC0_CPP_VERSION}" \
  && rzup install cargo-risczero "${RISC0_VERSION}" \
  && rzup install r0vm "${RISC0_VERSION}" \
  && rzup install risc0-groth16 "${RISC0_GROTH16_VERSION}"
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
