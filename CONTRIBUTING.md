# Contributing to AINCORE

The Rust workspace contains the node, consensus, execution and storage crates. Move sources and the bytecode used at genesis live in `core/vm_move/stdlib`. The TypeScript SDK lives in `aincore-js`. For a map of the components, see the [documentation index](docs/README.md).

## Build and test

From the repository root, use the Rust toolchain and system dependencies specified in the [node Dockerfile](Dockerfile). Keep the Cargo lockfile when building a candidate.

```sh
cargo build --release --locked --bin node
cargo test --locked -p node --lib public_claims_tests
```

For crypto changes, run the relevant unit tests. For executor changes, run `cargo test --locked -p executor`. Consensus quorum changes require a consensus review, and storage option changes require durability tests. The [release gate](docs/RELEASE_SECURITY_GATE.md) lists the checks used to qualify a candidate.

For SDK changes, run the following in `aincore-js` on a connected development machine.

```sh
npm ci
npm run build
npm test
```

The SDK lockfile pins the dependencies. The candidate also tracks the dependency tree used by offline checks and the JavaScript and type declarations listed in `package.json`. Verify the distributable file list with `npm run test:package`.

## Genesis and node data

Changes to the production genesis require explicit project-owner approval. The [economics contract](docs/G5_ECONOMICS_CONTRACT.md) defines what contributes to supply. Bootstrap voting weight has no corresponding coin balance. For a network join, obtain the genesis, its verified hash, the chain ID and the peer addresses for that network from its operator.

Keep node databases, wallet and validator keys, local environment settings and raw command transcripts on the operator's machine. Retain reviewed fixtures, published test vectors and evidence cited by release checks. See the [operator guide](docs/NODE_OPERATOR_GUIDE.md) and the [runtime package instructions](docs/RELEASE_PACKAGE.md).
