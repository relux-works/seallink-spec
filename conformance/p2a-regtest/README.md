# Namecoin Core 28 — P2A package relay test for SealLink

Positive check for OQ-006, exercised while reviewing SealLink `v1.0.0-draft.1` at `b15a9cbb443f2a982e2e34e217626eda040d7d1a`. See the [open qualification](https://github.com/relux-works/seallink-spec/blob/b15a9cbb443f2a982e2e34e217626eda040d7d1a/OPEN-QUESTIONS.md#L17).

## Measured configuration

Two fresh upstream Namecoin Core 28 regtest processes run with separate data directories, standard transaction policy, disabled wallets and a single loopback-only connection. The probe makes a normal transfer first and waits for peer B to see it before mining. A disposable test key signs a version-3 parent with zero fee, a return output and a 100,000-base-unit pay-to-anchor output. The separately funded version-3 child pays 500,000 base units. The source node rejects the parent alone for minimum relay fee. Only node A receives the two transactions through `submitpackage`. The test waits for both transactions in node B's mempool before asking A to mine, then verifies both transaction IDs in the block on B. An unmet acceptance condition raises an error.

## Reproduce

Use Python 3.13 with `coincurve==21.0.0`, binaries built from Namecoin Core `nc28.0`, and the matching upstream Python test framework. The review used a source-built arm64 macOS binary. The test takes the binary and framework paths explicitly. It generates disposable keys in memory, uses fresh temporary node data and stops its processes on exit. [Upstream release source](https://github.com/namecoin/namecoin-core/tree/a08218ef2d44b81c53d25c399898e59271f4b642)

```sh
python3 p2a_peer.py \
  --bin-dir /absolute/path/to/namecoin/bin \
  --framework-dir /absolute/path/to/nc28.0/test/functional \
  --output-dir /absolute/path/to/task-scratch/results
```

The output directory receives `p2a-peers-01.json` and the PIDs for this run. The two node data directories are removed after the processes exit. `observed-result.json` records the result of running the included script.

This exercises ordinary 1-parent/1-child relay on two local nodes with one parameter set. Independent operator administration, fee competition, production propagation and SealLink authorization are separate qualifications.
