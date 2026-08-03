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
| `app.py` | Flask API — `/api/alerts`, `/api/alerts/<id>`, `/api/stats`, `/api/submit-scan` |
| `dashboard.py` | Server-rendered views over the same data. **Its Jinja templates are not in this repository**, so the API is the working interface. |
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

The collection, processing, detection and alerting path is implemented and the Flask API
runs. Model definitions are here; no trained weights are included.

Known gaps, stated plainly:

- **The dashboard has no templates.** `dashboard.py` renders `index.html`, `alert_detail.html`,
  `scan.html` and `error.html`; none are in the repository, so every dashboard route raises
  `TemplateNotFound`. Use the API.
- **No CI, CloudFormation, packaged docs or benchmark suite.** `main.tf` covers the S3 bucket,
  two DynamoDB tables, the Kinesis stream, the SageMaker model and the Lambda processor.
- **`get_alerts` does not paginate.** `/api/stats` does; the alert list still returns one scan
  page.

### Notes from a correctness pass

Several defects were fixed rather than papered over, and they are worth knowing about if you
read the history:

- The LSTM was constructed for 64 input features while the preprocessor emits 12, so every
  forward pass raised a shape error. `input_dim` now derives from `get_expected_columns()`.
- The BERT head was built with two outputs against a six-category map, making four categories
  unreachable and making training on labels 2–5 index past the output layer.
- `DataProcessor` instantiated `BehavioralModel` without importing it.
- `timestamp` and `source` are DynamoDB reserved words. Used bare in a `FilterExpression` they
  raise `ValidationException`, so the alert queries and the statistics endpoint always failed.
  Both now go through `ExpressionAttributeNames`.
- Training with only normal activity is refused: under binary cross-entropy every label is 0
  and the model collapses to a constant, scoring perfectly on its own training set while
  detecting nothing.

## Licence

All rights reserved. Published for reading, not for reuse.
