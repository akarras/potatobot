# This docker file avoids using the rust provided images since we intentionally want to build for arm64/v8

FROM ubuntu:focal as builder
# Install system packages
RUN apt-get update; apt-get upgrade -y
RUN apt-get install -y cmake build-essential
RUN apt-get install -y sudo
RUN apt-get install libavcodec-dev libpostproc-dev libswscale-dev libavfilter-dev pkg-config libavdevice-dev libclang-dev libvpx-dev
RUN apt-get install ffmpeg libavutil-dev libavformat-dev 
# Configure rustup
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rust-src
RUN rustup update
RUN mkdir -p /app
WORKDIR /app
COPY . .
RUN cargo build --release

FROM ubuntu:focal as runner
COPY --from=builder /app/target/release/potatobot /app/
# copy font into local font dirs
RUN apt-get clean; rm -rf /var/lib/apt/lists/*;
WORKDIR /app
ENV RUST_LOG="info"
CMD ["/app/potatobot"]
