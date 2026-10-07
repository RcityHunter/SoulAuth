# SoulAuth 容器镜像。
#
# 每次推送由 CI 构建并跑通完整引导流程，见 .github/workflows/ci.yml 的 `docker` job。
#
# 分两段：编译产物有 ~1.5GB 的工具链和中间物，运行时一个都不需要。

# ── 构建 ─────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder

# oauth2 与 lettre 都启用了 native-tls，因此编译期需要 OpenSSL 开发头文件。
# 换成 rustls 可以省掉这一层，但那是依赖选型变更，不在容器化范围内。
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ⚠ **`rust-toolchain.toml` 必须在这里就进去,不能只拷 Cargo 清单。**(2026-10-07)
#
# 它是 2026-10-07 随 surrealdb 3.0.0 → 3.3.0 新建的:3.3.0 的 `surrealdb-common`
# 用 `std::hint::cold_path()`,**Rust 1.95.0 才稳定**。
#
# 不拷进来的后果不是「编不过」,而是更坏的那一种:上面是 `rust:1-bookworm`
# —— **浮动标签**,它解析到哪个 1.x 由构建当天决定。于是
# **本机与 CI 钉住了 1.95.0,而真正出厂的这个产物用另一个编译器编** ——
# 两边的绿说的不是同一件事,而这正是钉工具链本来要消除的那件事。
#
# ▎放在空壳那一步**之前**:依赖层是被 Docker 缓存复用的那一层,
#   钉子晚一步进来,缓存里留下的就是用错编译器编的依赖。
COPY rust-toolchain.toml ./

# 先只拷依赖清单并编译一个空壳，让依赖层能被 Docker 缓存复用 ——
# 否则改一行源码就要重编整棵依赖树。
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
# 上一步的空壳产物带着旧时间戳，不 touch 的话 cargo 会认为无需重编。
RUN touch src/main.rs && cargo build --release

# ── 运行 ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

# 不以 root 运行。认证服务被攻破时，容器内的 root 是攻击者最不该拿到的东西。
RUN useradd --system --create-home --uid 10001 soulauth
USER soulauth
WORKDIR /home/soulauth

COPY --from=builder /build/target/release/soulauth /usr/local/bin/soulauth

EXPOSE 8080

# `/health` 刻意注册在限流层之后，因此探针不会被 429 打回。
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["soulauth"]
