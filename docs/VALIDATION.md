# Local validation record

Validated on Windows with Python 3.11 and the pinned dependencies in a clean virtual environment. These results describe this workstation; the configured Linux/Windows CI jobs have not been run by this local session.

| Check | Result |
|---|---|
| Full pytest suite, pinned ONNX models present | 30 passed |
| Empty model cache, neural-specific tests excluded | 26 passed, 4 deselected |
| Real browser smoke test, headless Microsoft Edge | Passed |
| Dependency consistency, `pip check` | Passed |
| JavaScript syntax, `node --check static/js/app.js` | Passed |
| Patch whitespace, `git diff --check` | Passed |
| Demo seeder, first run | Three separate procedural records created; first signed |
| Demo seeder, repeat run | Existing records preserved |
| Docker build | Not run: local Docker daemon unavailable |

The browser test checks literal rendering of a hostile signer name, non-exportable IndexedDB key persistence across reload, client signing, server signature verification, and detail-page rendering. It uses an authenticated temporary server and isolated storage. CI is configured to use Chromium.

The API suite covers failed-signing atomicity, original retention, client public-key binding, plaintext legacy-key rejection, additive database migration, explicit legacy import, record/event/checkpoint tampering, deletion history, image limits, operator access, model checksum rejection, Merkle hashing, and evaluation calculations.

## Measurements and remaining limits

The [40-image procedural evaluation](../results/DATASET_ACCURACY_REPORT.md) recorded 95% fixture classification accuracy, with a Wilson 95% interval of 83.5–98.62%. Two periodic fixtures were falsely accepted. The false-acceptance, latency, and throughput targets failed. This is not an independently collected real-world dataset.

The [transformation benchmark](../results/BENCHMARK_REPORT.md) separates exact bytes, exact watermark identifiers, and perceptual candidate matches. Exact watermark recovery failed at JPEG quality 75 and 50 on its fixtures, even when candidate matching succeeded. Matching is not authenticated provenance.

Real-world dataset evaluation and calibration remain outstanding; follow [EVALUATION.md](../EVALUATION.md). Trusted C2PA issuance, validated timestamp trust, multi-user authorization, externally witnessed audit history, and production load testing are not implemented. The project is suitable for demonstrating an experimental engineering workbench with these limits stated explicitly.
