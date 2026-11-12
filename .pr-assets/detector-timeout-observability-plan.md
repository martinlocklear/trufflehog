# Plan: timeout-overrun observability for trufflehog detectors

**Repo:** [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) · **Date:** 2026-11-12

This plan adds the metrics and logs that identify detectors which hold workers past their timeout: which detector, how many workers, for how long, and why. It is instrumentation only. Detection results and ordering stay exactly as they are; the perf and log-volume deltas are named, not hidden.

## Why this exists

When a detector's `FromData` call ignores its context timeout, it keeps occupying one of the engine's detector workers, and enough occupied workers stall detection for every source at once. The existing overrun log line names the detector, but nothing counts overruns, times them, or shows how many workers are held at once, so an incident investigation has nothing to query. With this change, the next occurrence is a Prometheus query instead of log forensics, and the PrivateKey-specific metadata says whether the cost is what the benchmark predicts: encrypted keys cracked at round counts the key's author chose.

## Scope

**In:**

- `pkg/engine`: two new metrics, an overrun-duration histogram, one new log line, wired into the existing timeout timer in `detectChunk`.
- `pkg/detectors/privatekey`: a key-header metadata parser, one histogram, one debug log line, and an attempt count on the crack path.

**Out, with where it lives:**

- Making `Crack` honor its context, or capping and skipping cracks above a round count. Behavior fix, separate PR; this plan's metrics exist to size it.
- Distribution-side plumbing: the `go.mod` bump and verifying the metrics reach the scanner's production metrics output. Follow-on after upstream lands.
- Any production change: none. This PR touches only the public repo.

## Design: engine (`pkg/engine`)

### New metrics

Defined in `pkg/engine/metrics.go` beside the existing `promauto` vectors, using `common.MetricsNamespace` (`trufflehog`) and `common.MetricsSubsystem` (`scanner`), matching house style ([metrics.go](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/engine/metrics.go)):

| Metric | Type | Labels | Semantics |
|---|---|---|---|
| `trufflehog_scanner_detector_timeout_ignored_total` | Counter | `detector_name` | FromData calls whose overrun timer fired. |
| `trufflehog_scanner_detector_workers_over_timeout` | Gauge | `detector_name` | Workers currently inside a FromData call that overran the timer. |
| `trufflehog_scanner_detector_overrun_duration_seconds` | Histogram | `detector_name` | Full FromData duration for overrunning calls only. |

The histogram is committed (not optional): the existing `detector_execution_duration` buckets (`ExponentialBuckets(1, 5, 6)` ms) top out at about 3.1 s, so every overrun lands in `+Inf` today and cannot be timed. Proposed buckets: `ExponentialBuckets(10, 2, 10)`, covering 10 s to about 85 min.

Label cardinality: `detector_name` is bounded by the compiled-in detector set, the same dimension the existing duration metric already uses. Gauge series appear lazily on first overrun - before that, the gauge is absent rather than zero, and any ratio needs to tolerate the empty numerator.

One semantics note that must reach the help strings: the overrun timer fires at `detectionTimeout + 1s`, so "over timeout" means past the grace deadline, not merely past the timeout. The gauge is the numerator; the denominator is the configured pool size already exposed as `engine_worker_count{worker_type="detector_workers"}` by the runtime collector. The stuck-vs-total ratio needs matching help because the labels differ, for example:

```
sum(trufflehog_scanner_detector_workers_over_timeout)
  / sum(trufflehog_scanner_engine_worker_count{worker_type="detector_workers"})
```

### The change in `detectChunk`

The existing code arms `time.AfterFunc(detectionTimeout+1*time.Second, ...)` to log when a detector ignores its timeout, then calls `t.Stop()` and discards the result. The new bookkeeping attaches to that same timer, and the interesting part is the handoff between the callback and the return path.

`t.Stop()` returning false means the callback started, not that it finished. A naive design that checks a flag in the return path leaks the gauge: the return path can read the flag before the callback sets it, skip its decrement, and the callback then increments into a gauge nobody will ever bring back down. The fix is to make the return path wait for the callback to finish counting:

```go
fired := make(chan struct{})
t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
    detectorTimeoutIgnoredTotal.WithLabelValues(detectorNameStr).Inc()
    detectorWorkersOverTimeout.WithLabelValues(detectorNameStr).Inc()
    close(fired) // before the log: a slow log sink must not extend the worker hold
    ctx.Logger().Error(nil, "a detector ignored the context timeout")
})
matchStart := time.Now()
results, err := e.verificationCache.FromData(/* unchanged */)
matchElapsed := time.Since(matchStart)
if !t.Stop() {
    <-fired
    detectorWorkersOverTimeout.WithLabelValues(detectorNameStr).Dec()
    detectorOverrunDuration.WithLabelValues(detectorNameStr).Observe(matchElapsed.Seconds())
    ctx.Logger().V(2).Info("detector returned after overrunning the context timeout",
        "duration", matchElapsed.String())
}
cancel()
```

The wait only happens on overruns. Because `close(fired)` precedes the log call, the wait is bounded by two counter increments even when the log sink is slow; the fire and return lines may occasionally reorder, which is harmless. The existing context fields (`detector`, `decoder_type`, `chunk_source_*`) ride both log lines for free through `ctx.Logger()`, because `detectChunk` already installs them via `context.WithValues`.

Two known edges, both acceptable and worth a comment in the code:

- **Panic.** If `FromData` panics, the return path never runs, so the gauge increments without its decrement and sits high until process restart. `detectChunk`'s existing `defer common.Recover(ctx)` means the process survives; the existing code has the same shape (`t.Stop()` and `cancel()` are skipped on panic today). Accept with a comment; hardening with a per-match closure is available if upstream wants it.
- **Zero-allocation alternative.** The per-match `make(chan struct{})` costs roughly 50-100 ns plus GC on every match (estimated, not benchmarked). A two-counter variant (`_ignored_total` in the callback, `_returned_total` on the return path, live count derived as the difference in PromQL) removes the allocation entirely at the cost of a microsecond-scale negative transient a scrape could theoretically catch. The gauge wins unless a profile ever shows the allocation matters; flagged so the implementer does not quietly pick the racy-looking one.

### Logs

| Message | Level | When | Volume bound |
|---|---|---|---|
| `a detector ignored the context timeout` | Error (unchanged) | Timer fires while FromData still runs | Per overrunning worker: at most one per timeout + grace (11 s at defaults). Pod ceiling: about 2 × pool / 11 s while every worker overruns. |
| `detector returned after overrunning the context timeout` | V(2) (new) | FromData returns after the timer fired | Same bound; debug-only, so the production Error stream is unchanged. |

Both lines use static messages with dynamic fields. The fire log stays Error as today.

The level recommendation for the return line: overruns are not exotic. An encrypted OpenSSH key at default KDF settings takes about 24 s per pass through the 248-word passphrase list against the 10 s detection timeout, so ordinary encrypted-key content triggers overruns and the fire line already fires at content density. Doubling that Error stream with a second line per event is a volume regression the metrics make unnecessary - the histogram carries duration, which was the second line's production value. Recommendation: V(2), with the fire log unchanged as the production signal.

## Design: PrivateKey (`pkg/detectors/privatekey`)

`Crack` ([cracker.go](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/privatekey/cracker.go)) walks a 248-word passphrase list with no context, and for OpenSSH keys every attempt runs bcrypt at the round count stored in the key file, which the key's author chose, not us. Those round counts are what make a crack expensive, and x/crypto does not expose them, so the detector reads them from the key header itself.

**New file `keymeta.go`** with a defensive parser over the non-secret OpenSSH header:

```go
type keyMetadata struct {
    format    string // "openssh", "pem", "unknown"
    cipher    string // e.g. "aes256-ctr"; empty for legacy PEM
    kdf       string // e.g. "bcrypt"; empty for legacy PEM
    kdfRounds uint32 // 0 when format is not openssh
}

// parseKeyMetadata reads non-secret header fields from a PEM-encoded
// private key without decrypting it. It never returns key material.
func parseKeyMetadata(key []byte) (keyMetadata, bool)
```

The OpenSSH binary layout is short and stable: PEM decode, the `openssh-key-v1\0` magic, then length-prefixed strings for cipher name, KDF name, and KDF options (salt length, salt bytes, rounds). The length prefixes are attacker-controlled (a declared length of 0xFFFFFFFF must parse or fail without panicking), so the parser checks every read against the buffer. Any truncation or unexpected shape reports format `unknown` rather than erroring. Cost is a PEM decode of at most 4 KB (the detector's `MaxSecretSize`), once per encrypted key.

**Crack keeps its exported signature; the attempts count moves to an unexported helper.** `Crack` is a public symbol in a public package, and a second in-repo caller exists: the privatekey analyzer (`pkg/analyzer/analyzers/privatekey/privatekey.go:65`) also calls `Crack`. Changing the exported signature would break that caller and any external importer. Design: `Crack(in []byte) (any, string, error)` stays as a thin wrapper over `crack(in []byte) (any, string, int, error)`, which returns the attempt count; the detector's `FromData` calls `crack` directly and instruments it. The analyzer path keeps the wrapper and its behavior is unchanged.

**Wiring in `FromData`,** immediately around the crack call: parse the header, time the call, observe the histogram, log once at `V(2)`:

- Metric: `trufflehog_scanner_privatekey_crack_duration_seconds{format, kdf_rounds}`. `format` is `openssh` / `pem` / `unknown`; `kdf_rounds` is bounded: `<=16` / `<=256` / `>256` / `unknown` (rounds are attacker-controlled uint32 header values; raw counts never become labels). Round-count boundaries are estimated against the 10 s detection line from the benchmark and should be re-checked when the benchmark is rerun. Histogram buckets: `ExponentialBuckets(0.05, 4, 9)` (50 ms to about 55 min), covering both the 16-round default (about 24 s for the full list) and 2048-round keys (about 50 min).
- Log: `V(2)` with fields `format`, `cipher`, `kdf`, `kdf_rounds`, `attempts`, `outcome` (`cracked` / `uncrackable` / `failed`), `duration`. Debug-only; one line per encrypted key found, never per passphrase attempt.
- Secret hygiene, absolute: log only the metadata above. Never the key bytes, the salt, the passphrase list, any candidate passphrase, or the cracked result.
- Limitation stated in the PR: the histogram times `Crack` only, so it cannot distinguish slow cracking from a slow verifier; paired with the engine's overrun metrics, small crack durations with an engine overrun point at the verifier.

**The new-pattern question.** No detector package registers a Prometheus metric today (engine-level metrics are an established, merged pattern: [#5526](https://github.com/trufflesecurity/trufflehog/pull/5526), [#5341](https://github.com/trufflesecurity/trufflehog/pull/5341), [#2312](https://github.com/trufflesecurity/trufflehog/pull/2312)). The PR argues the case first - only the detector can see format and rounds, and the labels are bounded - and puts the fallback last: dropping the detector histogram loses crack-duration data for calls that do not overrun (the engine histogram covers overruns only), leaving the `V(2)` log as the sole source. That tradeoff needs an explicit decision if upstream declines the pattern.

## Tests

**Engine** (`pkg/engine`):

- A slow fake detector following the `fakeDetectorV1` shape, whose `FromData` sleeps.
- Overrun test: `SetDetectorTimeout(10 * time.Millisecond)` with a deferred restore, detector sleeps about 1.2 s. The 1 s grace matters here: the callback fires at about 1.01 s, so a sleep that only exceeds the bare timeout never fires the timer and the test would pass for the wrong reason. This is the one test over a second, and it runs serially - `detectionTimeout` is a package global, so these tests must not use `t.Parallel()` and must restore the value via defer.
- Assertions: `detector_timeout_ignored_total` for the label equals 1 (`prometheus/testutil`), the gauge returns to 0 after `FromData` returns, the gauge reads 1 mid-flight via `assert.Eventually`, and a captured logr sink shows both log lines.
- No-overrun test: fast detector, default timeout, counter 0 and gauge 0.

**PrivateKey** (`testdata/` fixtures, committed once, generated from throwaway keys; never a real key, passphrase something obvious like `trufflehog-test-fixture`):

- Encrypted OpenSSH ed25519 key at `-a 16` for parse and crack tests; a `-a 2048` key for parse-only tests (never cracked in tests, so it stays fast); a legacy PEM key via `-m PEM`; an unencrypted key; a truncated key for the `unknown` path; a hostile header with a declared length of 0xFFFFFFFF for the panic-free path.
- Assertions: parsed format, cipher, KDF, and rounds for each fixture; `FromData(ctx, false, ...)` with a 1-round key observes the histogram and emits the `V(2)` line; the uncrackable outcome still observes and logs; a log-capture test asserts the fixture passphrase and salt never appear in any log line or metric label. With `verify=false` there is no network.

## Validation gate

`go build ./...`, then `go test ./pkg/engine/... ./pkg/detectors/privatekey/...`, then `golangci-lint run` (repo ships a `.golangci.yml`).

## Performance budget

Detection results and ordering are unchanged. The always-on cost per match is one channel allocation of roughly 50-100 ns (estimated, not benchmarked) and its GC, inside a code path that already allocates a timer and does regex plus possible network I/O in `FromData`. The overrun path adds a wait for the callback's two increments (bounded by the callback's scheduling start) and one metric observe. Overruns are not rare events: ordinary encrypted-key content at default KDF settings overruns the 10 s timeout, so the fire log's volume scales with content density up to the pod ceiling - which is the existing fire line's behavior, unchanged by this PR. The PrivateKey header parse runs once per encrypted key; unencrypted keys and all other detectors see nothing new. Worker counts, channel sizes, and concurrency are untouched.

## Upstream acceptance

The timeout-ignoring behavior is already known upstream: [#3215](https://github.com/trufflesecurity/trufflehog/issues/3215) (open, "timeout issues"; its trace shows the existing line carrying the detector name) and [#3714](https://github.com/trufflesecurity/trufflehog/issues/3714) (FTP detector variant, closed). The change is additive with the deltas named. The one genuinely novel element is detector-level metrics, argued first with the fallback last.

## Follow-ons (out of scope, noted)

- Distribution side: `go.mod` bump; surface the over-timeout gauge in the scanner's runtime metrics; confirm the metrics-push path re-exposes new metrics.
- Behavior fix PR: context-aware `Crack`, round caps - separate, sized by this PR's metrics.
