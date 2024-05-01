# This docker file avoids using the rust provided images since we intentionally want to build for arm64/v8

FROM debian:bookworm as builder
# Install system packages
RUN apt update; apt upgrade -y
RUN apt install -y libfreetype6 libfreetype6-dev cmake build-essential curl sudo
# Configure rustup
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rust-src
RUN rustup update
RUN mkdir -p /app
WORKDIR /app
RUN apt install -y ffmpeg libavutil-dev libavformat-dev libavcodec-dev libpostproc-dev libswscale-dev libswresample4 libswresample-dev libavfilter-dev pkg-config libavdevice-dev libclang-dev libvpx-dev
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim as runner
COPY --from=builder /app/target/release/potatobot /app/
# copy font into local font dirs
RUN apt-get clean; rm -rf /var/lib/apt/lists/*;
WORKDIR /app
ENV RUST_LOG="info"
CMD ["/app/potatobot"]
