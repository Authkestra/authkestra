# Contributing to Authkestra

Thank you for your interest in contributing to Authkestra! We welcome contributions of all kinds, from bug reports and documentation improvements to new features and framework integrations.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) (for running integration tests with Redis/SQL)

### Setting Up the Development Environment

1. Clone the repository:

    ```bash
    git clone https://github.com/Authkestra/authkestra.git
    cd authkestra
    ```

2. Run the dependencies using Docker Compose:

    ```bash
    docker-compose up -d
    ```

3. Run the tests to ensure everything is set up correctly:

    ```bash
    cargo test --workspace --all-features
    ```

    Some integration tests use [testcontainers](https://docs.rs/testcontainers) and need a
    reachable Docker daemon. Under rootless Docker, point `DOCKER_HOST` at your user socket
    (e.g. `export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock`) or those tests will fail
    with a permission error.

## Development Workflow

1. **Create a Branch**: Create a new branch for your changes.

    ```bash
    git checkout -b my-feature-branch
    ```

2. **Make Changes**: Implement your changes, ensuring you follow the project's coding style and include documentation for any new public APIs.

3. **Run Lints and Formatting**: these are exactly the commands CI runs, so run them verbatim
   rather than an approximation.

    ```bash
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features -- -D warnings
    ```

4. **Run Tests**: Ensure all tests pass, including any new tests you've added.

    ```bash
    cargo test --workspace --all-features
    ```

    CI additionally enforces a line-coverage floor and the `deny.toml` dependency policy:

    ```bash
    cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 84
    cargo deny check
    ```

5. **Submit a Pull Request**: Push your branch to your fork and submit a pull request to the `main` branch of the main repository.

## Documentation

We use `cargo doc` to generate API documentation. Please ensure that all public APIs are documented with clear and concise doc comments. You can preview the documentation locally by running:

```bash
cargo doc --workspace --no-deps --open
```

## License

By contributing to Authkestra, you agree that your contributions will be licensed under the project's dual MIT and Apache-2.0 licenses.
