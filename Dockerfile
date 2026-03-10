FROM rust:1.90-bookworm AS build
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
RUN curl -L https://risczero.com/install | bash
ENV PATH="/root/.risc0/bin:${PATH}"
RUN rzup install
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
