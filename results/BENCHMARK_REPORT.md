# ImageGuard procedural regression benchmark

These generated patterns exercise code paths. They are not captured photographs or generator outputs, and establish no real-world detection accuracy or platform-wide watermark survivability.

| Fixture class | N | Mean score | Fixture classification accuracy (%) |
|---|---:|---:|---:|
| natural | 10 | 73.31 | 90.0 |
| spliced | 10 | 16.26 | 100.0 |
| synthetic | 10 | 15.74 | 100.0 |

Mean pipeline latency: 834.82 ms; p95: 874.06 ms.

| Transform | Exact bytes preserved (%) | Exact watermark recovery (%) | Candidate dHash recovery (%) |
|---|---:|---:|---:|
| 1. Direct Transfer | 100.0 | 100.0 | 100.0 |
| 2. Metadata Strip (Lossless) | 0.0 | 100.0 | 100.0 |
| 3a. JPEG Re-encode (QF=90) | 0.0 | 100.0 | 100.0 |
| 3b. JPEG Re-encode (QF=75) | 0.0 | 0.0 | 100.0 |
| 3c. WhatsApp / JPEG (QF=50) | 0.0 | 0.0 | 100.0 |
| 4. Luminance Shift (+10%) | 0.0 | 100.0 | 100.0 |
| 5. Localized 15% Splice | 0.0 | 0.0 | 90.0 |

Candidate matching does not authenticate a derivative. JPEG quality settings simulate a transformation, not a measurement of a live social platform.

| Tree leaves | Proof nodes for selected leaf | Build and proof (ms) | Verify (ms) |
|---|---:|---:|---:|
| 10 | 4 | 0.015 | 0.005 |
| 100 | 7 | 0.131 | 0.007 |
| 1000 | 10 | 1.285 | 0.009 |
| 5000 | 13 | 6.473 | 0.012 |

This measures Merkle primitives, not concurrent server throughput or protection against a compromised signing host. Full metrics are in benchmark_metrics.json.
