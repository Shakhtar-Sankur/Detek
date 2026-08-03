# Detek

**Data-leak detection for AWS: collect telemetry, classify content, model user behaviour,
and raise prioritised alerts.**

A reference implementation of a detection pipeline that watches CloudTrail and VPC Flow
Logs, scores activity with two learned models, and routes the results to an alert
manager and a small web dashboard.

## What's here

| File | Role |
|---|---|
| `cloudtrail_collector.py` | Pulls CloudTrail events — the service-level view of who did what |
| `vpc_flow_collector.py` | Pulls VPC Flow Logs — the network view of what moved where |
| `data_processor.py` | Normalises both sources into a common feature representation |
| `content_classifier.py` | `BERTClassifier` over a `SensitiveContentDataset`, for spotting sensitive material in transferred content |
| `behavioral_model.py` | `LSTMAnomalyDetector` over `UserActivityDataset`, for sequence anomalies in per-user activity |
| `alert_manager.py` | Deduplication, severity scoring and routing |
| `app.py` | Flask API — `/alerts`, `/alerts/<id>`, `/stats`, `/scan` |
| `dashboard.py` | Server-rendered views over the same data |
| `main.tf` | Terraform for the AWS resources the collectors read from |

Two detectors rather than one is the central design choice. Content classification alone
flags every legitimate transfer of a sensitive document; behavioural modelling alone
misses a first-time exfiltration that looks procedurally normal. The pipeline is built so
their scores combine.

## Design targets

- Sustain ~120K security events per day
- Precision high enough that alerts stay actionable rather than ignored
- Cut mean time to detect from hours to minutes

## On the numbers

The figures above are **design targets** that shaped the implementation — they are not
measured results. This repository ships no benchmark harness and no trained weights, so
nothing here reproduces them. They are recorded because they drove real decisions about
architecture and algorithm choice, not as claims about observed performance.

## Running it

```bash
pip install -r requirements.txt
python app.py          # API on :5000
python dashboard.py    # dashboard
```

Both expect AWS credentials in the environment and the resources in `main.tf` to exist.
The models are defined here but no trained weights are included.

## Status

Working implementation of the collection, processing, detection and alerting path. Not a
deployed system: there are no CI pipelines, CloudFormation templates, packaged docs or
benchmark suite in this repository.

## Licence

All rights reserved. Published for reading, not for reuse.
