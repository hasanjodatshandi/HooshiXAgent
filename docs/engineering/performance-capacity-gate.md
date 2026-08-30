# R-12 Performance and Capacity Gate

## Purpose and scope

R-12 establishes reproducible performance evidence for the existing HooshiX Agent/Gateway architecture. It does **not** introduce a new orchestrator, Control Panel service, Redis/Kubernetes layer, protocol version, routing model, or correctness/security bypass. Correctness, security and resource-budget gates remain mandatory.

The gate separates two questions:

1. **Current production safety envelope** — the shipped Gateway defaults remain explicit bounded safety controls.
2. **Synthetic scaling probe** — tests temporarily raise only count/rate limits in-process to measure whether the current engine can coordinate 100/500/1000 concurrent streams/requests or resident sessions. Those test-only limits are not production recommendations.

## Reproducible commands and evidence

`scripts/ci/performance-capacity.sh` produces an evidence directory containing:

- `environment.txt` — exact Git SHA, Go version, OS/CPU visibility and soak/profile durations;
- `capacity.txt` — three repeated 32/100/500/1000 request+stream probes plus 64/100/500/1000 resident WSS-session probes;
- `benchmark.txt` — three allocation/latency benchmark samples;
- `soak.txt` — sustained public round-trip benchmark (10 seconds in the default CI gate);
- `cpu.pprof`, `heap.pprof`, `block.pprof`, `mutex.pprof` plus symbolized `*-top.txt` summaries;
- `acceptance.txt` — the stable regression policy used by the gate.

CI uploads the complete directory as `r12-performance-<commit-sha>`.

## Stable acceptance policy

The automated R-12 gate requires:

- zero request/session errors in the capacity probes;
- successful reachability and cleanup at 32, 100, 500 and 1000 simultaneous tunneled requests/streams;
- successful coexistence and cleanup at 64, 100, 500 and 1000 resident authenticated WSS sessions under test-only session limits above the shipped default;
- synthetic capacity-probe p99 at or below **5 seconds**;
- a sustained benchmark completing with zero HTTP/tunnel errors;
- non-empty CPU, heap, block and mutex profiles.

A fixed ns/op or requests/second floor is intentionally **not** used as a required CI threshold because shared hosted-runner speed varies materially. Benchmark throughput/allocation values are retained as evidence and reviewed across commits. Security/correctness gates are never weakened to meet a performance number.

## Reference development evidence

On the reference local WSL2 development run (Go 1.27.0, Linux amd64, 8 logical CPUs visible to WSL), three repeated synthetic request/stream probes produced:

| Concurrent requests/streams | representative p99 | observed peak heap in combined in-process test |
| ---: | ---: | ---: |
| 32 | 6.7–51 ms | 4–29 MiB |
| 100 | 22–44 ms | 11–20 MiB |
| 500 | 107–131 ms | 59–62 MiB |
| 1000 | 220–224 ms | 112–123 MiB |

The resident-session probe reached 1000 simultaneous authenticated WSS sessions in about **1.59 seconds** at roughly **629 sessions/second**, with approximately **71–82 MiB** peak heap in the combined Gateway+test-peer process. These values are reference evidence, not a promise for production hosts or Internet clients.

The three ordinary public round-trip benchmark samples were approximately **110–130 µs/op**, **67–72 KiB/op**, and **404–407 allocs/op**. A five-second local sustained run completed about 59k operations at approximately **125 µs/op** with zero request errors. CI uses a longer ten-second soak by default.

## Merged-main hosted-runner evidence

The R-12 artifact uploaded by merged-main CI for merge `0e3d299e493b41e48c98616253e677b4f62893d9` recorded Go 1.27.0 on Linux amd64 with four logical CPUs. Three 1000-request probes reported p99 values of approximately **1.028 s**, **1.071 s**, and **1.027 s**. Three 1000-resident-session probes connected in approximately **2.776 s**, **2.714 s**, and **2.709 s**, or about **360–369 sessions/second**. Ordinary public round-trip samples were approximately **156–161 µs/op** on that shared runner.

The same artifact contains non-empty CPU, heap, block and mutex profiles plus symbolized top reports, and explicitly records `production_defaults_unchanged=true`. Hosted-runner results are synthetic regression evidence, not production guarantees.

## Profile interpretation

The reference CPU profile was dominated by kernel/syscall and Go runtime scheduling/I/O costs rather than one Gateway compute function. Allocation-space profiling showed the largest costs in buffered HTTP reader/writer creation, MIME/header parsing, context lifecycle, and test-peer work; `newStream` and `session.sendFrame` were visible but not dominant. Block time was expectedly dominated by network/channel `select` waits; the Gateway ingress/stream read paths appeared cumulatively because this benchmark is an I/O pipeline. Mutex profiling did not identify a single production Gateway mutex as the dominant lock hotspot; much of the observed contention belonged to the in-process mock peer.

Therefore R-12 does not justify a production algorithm rewrite or queue/budget increase from these profiles alone.

## Capacity defect found and fixed by R-12

The first resident-session probe stopped exactly at session 65 even when `MaxAgentSessions` was raised. R-12 traced this to `MaxPendingHandshakes`: the Gateway held a pending-handshake slot for the **entire authenticated session** because the slot release was deferred until `session.run` returned.

R-12 releases the pending-handshake slot immediately after authentication completes (success or failure paths remain bounded/fail-closed). A dedicated regression sets `MaxPendingHandshakes=1`, keeps the first authenticated session alive, and proves a second session can authenticate while the pending-handshake count returns to zero. Existing pending-handshake exhaustion behavior remains green for genuinely incomplete handshakes.

## Production envelope and tuning decision

R-12 deliberately leaves the shipped runtime defaults unchanged:

- `MaxAgentSessions = 64`
- `MaxStreamsPerSession = 64`
- `MaxIngressInFlight = 32`
- ingress rate = 256 requests/second, burst 512
- handshake rate = 32/second, burst 64
- stream/session/global byte budgets remain the R-3 values
- Gateway Compose ceiling remains 256 MiB / 1 CPU / 256 PIDs from R-10

The 100/500/1000 probes demonstrate scaling headroom in a local, in-process, loopback environment after the handshake-slot defect is fixed; they do **not** reproduce Internet RTT, many physical Agent hosts, Caddy TLS edge cost, heterogeneous local services, or a 1-CPU/256-MiB container boundary. Increasing production defaults from that evidence would overstate what was measured.

The accepted production capacity envelope therefore remains the existing bounded defaults. Operators requiring a larger envelope must repeat the R-12 evidence on representative deployment hardware/workload before changing limits. R-13 reconciles this result into the current README/runtime/operations documentation without changing the measured defaults.
