# ImageGuard evaluation report

**Source:** procedural_regression
**Samples:** 40
**Accuracy Wilson 95% interval:** [83.5, 98.62]

Procedural fixtures test regressions, not real camera or generator accuracy. External folders use supplied labels; source independence and train/test separation require a dataset audit. Scores are uncalibrated. Targets below are project goals, not industry standards.

| Metric | Measured | Project target | Status |
|---|---:|---:|---|
| Accuracy (%) | 95.0 | >= 90 | PASS |
| Precision (%) | 90.91 | >= 90 | PASS |
| Recall, authentic positive (%) | 100.0 | >= 90 | PASS |
| Specificity (%) | 90.0 | >= 90 | PASS |
| False acceptance rate (%) | 10.0 | <= 5 | FAIL |
| F1 | 0.9524 | >= 0.9 | PASS |
| ROC-AUC | 0.9625 | >= 0.95 | PASS |
| Mean latency (ms) | 1057.6 | <= 250 | FAIL |
| Sequential throughput (images/sec) | 0.95 | >= 4 | FAIL |

## Cohorts

| Cohort | N | Accuracy (%) |
|---|---:|---:|
| Procedural camera-like pattern | 10 | 100.0 |
| Procedural landscape pattern | 10 | 100.0 |
| Localized Splices | 10 | 100.0 |
| Procedural periodic pattern | 10 | 80.0 |

## Misclassifications

- `ai_slop_03`: supplied label synthetic; prediction Authentic Media; score 84.31
- `ai_slop_07`: supplied label synthetic; prediction Authentic Media; score 80.69

## Reproducibility

```json
{
  "source_kind": "procedural_regression",
  "python": "3.11.9",
  "platform": "Windows-10-10.0.26200-SP0",
  "models": {
    "cifake": {
      "revision": "2235b7af38d04956416238554080494d84091552",
      "repo": "cftcimert/cifake-efficientnet-b0",
      "status": "loaded_checksum_verified"
    },
    "detectra": {
      "revision": "c84565e5bf8969d95908e12844f551e77ae87105",
      "repo": "s-gehring/detectra-openfake",
      "status": "loaded_checksum_verified"
    }
  },
  "positive_class": "authentic",
  "scores_calibrated": false,
  "dataset_sha256": "439f30089119e92e4b1e112c5826ff19514864fa00c7cddaaad51e0ac098c056",
  "external_generalization_established": false,
  "transform": "original"
}
```
