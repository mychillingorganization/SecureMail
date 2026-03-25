# Model Training Pipeline

This folder contains training-only assets and evaluation data, isolated from runtime services.

## Layout
- file_agent/: training scripts/features for file models
- email_agent/: notebook and email model evaluation assets
- web_agent/: web model evaluation assets
- data/: optional intermediate training outputs

## Notes
- Do not mount this folder in production containers.
- Runtime inference models must stay inside each owning agent folder:
  - FILE_AGENT/file_agent/models/
  - email_agent/models/
  - web_agent/models/
