# Contributing to scorehsm

## Getting Started

```bash
# Clone
git clone https://github.com/Taktflow-Systems/scorehsm.git
cd scorehsm

# Run host tests (stable Rust)
cargo test --workspace --features mock

# Check firmware compiles (nightly Rust + ARM target)
cd firmware
rustup target add thumbv8m.main-none-eabihf
cargo check --release
```

## Development Workflow

1. Create a feature branch: `feat/<description>` or `fix/<description>`
2. Write tests first (TDD enforced)
3. Run the full gate before pushing:
   ```bash
   cargo test --workspace --features "mock,certs"
   cargo clippy --workspace --all-targets --features "mock,certs" -- -D warnings
   cargo fmt --all -- --check
   ```
4. Open a PR against `main`

## Code Standards

- **Rust edition**: 2021
- **Host crate**: stable toolchain, `#![deny(missing_docs)]`, `#![deny(unsafe_code)]`
- **Firmware crate**: nightly (Embassy requirement), `#![no_std]`
- **Formatting**: `rustfmt` with project `rustfmt.toml`
- **Linting**: zero clippy warnings (`-D warnings`)
- **Tests**: all new code must have corresponding tests
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) format

## Safety-Critical Code

This project targets ASIL B per ISO 26262. Changes to safety-relevant modules
(`safety.rs`, `transport.rs`, `session.rs`, `keystore.rs`) require:

- Traceability to a requirement (FSR or TSR)
- Test coverage for the changed code path
- Review of the safety impact

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.
