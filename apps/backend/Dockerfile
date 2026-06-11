FROM rust:1-trixie AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && printf 'fn main() { println!("build stub"); }\n' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

WORKDIR /app

COPY --from=builder /app/target/release/backend /usr/local/bin/backend

ENV BACKEND_HOST=0.0.0.0
ENV BACKEND_PORT=4000

EXPOSE 4000

USER appuser

CMD ["backend"]