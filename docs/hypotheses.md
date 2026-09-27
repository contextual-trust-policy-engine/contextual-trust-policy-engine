# Claims tested

All results below come from committed artifacts under `results/`.

| ID | Claim | Result | Outcome |
|---|---|---|---|
| Claim 1 | Policy evaluation p50/p95/p99 <= 3/8/15 ms | 10k-rule in-process p50 0.111 ms, p95 0.290 ms, p99 0.319 ms | Met |
| Claim 2 | Hybrid trust Brier < every single method | hybrid 0.3349; Wilson 0.3349; EWMA 0.0955; Dirichlet 0.1940 | Not met |
| Claim 3 | Relationship check p99 grows sub-linearly in tuple count | in-process 1e3 p99 0.001775 ms; 1e6 p99 0.001177 ms | Met |
| Claim 4 | Benchmark v4 blocks attacks, keeps false-positive rate low, and leaks 0 | block 0.900 (450/500, Wilson [0.871, 0.923]); false-positive rate 0.008 (4/500, Wilson [0.003, 0.020]); leaks 0 | Improved, not met |

TLC: 471756 generated, 101812 distinct, depth 16, no violations. Benchmark dataset: `zero-trust-agent-benchmark-dataset-v4.1`; `test.jsonl` sha256 `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`. The dev split in `results/benchmark-dev` was used for threshold tuning only; the test split in `results/benchmark-test` is reported.

## Claim 1 policy latency

`AbacEngine` builds an exact-tool index at rule compilation time and evaluates only rules for the requested tool plus glob-pattern rules. The direct 10k-rule result is p50/p95/p99 0.111/0.290/0.319 ms in-process. HTTP timings are reported separately because host scheduling and container load can dominate loopback calls.

## Claim 2 trust reliability

`results/reference-run/summary.json` stores `trust_reliability`: Brier scores, reliability curves, and a fitted-weight sensitivity run over dev trust histories. The hybrid score underperforms EWMA on this dataset because the 500 dev histories contain 2745 outcomes and are short enough that the score stays in the cold-start branch. In that branch, hybrid equals the conservative Wilson lower bound. A grid fit over Wilson, EWMA, and Dirichlet components selects EWMA weight 1.0 with Brier 0.0955; the fixed warm-path Wilson/Dirichlet weights score 0.2457.

## Claim 4 benchmark v4

The adapter uses identity, attestation, scope, trust thresholds, egress allowlists, issued-secret data-flow checks, unsafe secret-reference checks, Unicode control checks, chat-template control checks with zero reasoning, malformed structured-frame checks, raw-generation frame checks, untrusted content taint checks, and requester-authority checks for shell and secret access. The final test split blocks 450/500 attack traces with no leaks. False positives remain 4/500 = 0.008 (Wilson [0.003, 0.020]).

Dev-split miss analysis before the changes showed misses concentrated in in-policy prompt injection, privilege escalation, tool hijack, and parser confusion. After the changes, dev split block rate is 224/250 = 0.896, with remaining misses by family and slice: prompt injection in-policy 12, tool hijack in-policy 10, tool hijack out-of-policy 3, and privilege escalation in-policy 1.

Defense ablation on the test split:

| Version | Block rate | False-positive rate | Leak rate | p95 latency |
|---|---:|---:|---:|---:|
| Version 1 | 0.766 [0.727, 0.801] | 0.008 [0.003, 0.020] | 0.000 [0.000, 0.004] | 0.392 ms [0.367, 0.426] |
| + raw-generation frame checks | 0.806 [0.769, 0.838] | 0.008 [0.003, 0.020] | 0.000 [0.000, 0.004] | 0.393 ms [0.363, 0.423] |
| + untrusted content taint checks | 0.848 [0.814, 0.877] | 0.008 [0.003, 0.020] | 0.000 [0.000, 0.004] | 0.656 ms [0.558, 0.836] |
| Final requester-authority checks | 0.900 [0.871, 0.923] | 0.008 [0.003, 0.020] | 0.000 [0.000, 0.004] | 0.528 ms [0.479, 0.596] |

The 100% attack-block claim is still not met. The remaining failures are mostly in-policy requests whose visible fields do not carry enough structured user-intent or resource-ownership evidence to distinguish the malicious tool effect from legitimate high-risk work without increasing false positives.
