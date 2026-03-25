# Model Training Pipeline

This folder contains training-only assets and evaluation data, isolated from runtime services.

## Layout
- file_module/: training scripts/features for file models
- email_module/: notebook and email model evaluation assets
- web_module/: web model evaluation assets and merged web training artifacts
- data/: optional intermediate training outputs

## Notes
- Do not mount this folder in production containers.
- Runtime inference models must stay inside each owning agent folder:
  - file_module/file_module/models/
  - email_module/models/
  - web_module/models/
