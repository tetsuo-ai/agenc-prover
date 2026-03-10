FROM rust:1.90-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release -p agenc-prover-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home app
COPY --from=build /app/target/release/agenc-prover-server /usr/local/bin/agenc-prover-server
USER app
ENV PROVER_HOST=0.0.0.0
ENV PROVER_PORT=8787
EXPOSE 8787
CMD ["agenc-prover-server"]

