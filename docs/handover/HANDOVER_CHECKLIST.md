# Handover Checklist

## Included in this archive
- Watermarking implementation files available in the packaging workspace
- CNN model definition and checkpoint
- Watermarking test helpers and sample assets
- Final validation report and aggregate CNN threshold summary

## Still to copy from the project machine if the team requires them
- `src/create_cnn_dataset.py`
- `src/train_watermark_cnn.py`
- `src/test_cnn_robustness.py`
- `src/test_cnn_independent.py`
- `src/test_cnn_external.py`
- `src/test_cnn_clean_independent.py`
- `src/analyze_cnn_results.py`
- `cnn_independent_results.csv`
- `cnn_threshold_results.csv`
- `cnn_clean_independent_results.csv`
- Raw run logs as applicable

## Safe handling
- Do not run the dataset generator without first backing up `cnn_dataset`; it deletes and recreates that directory.
- Do not overwrite `watermark_cnn.pth` unless intentionally retraining and preserving the current checkpoint.
- The threshold summary is aggregate historical evidence. It is not a replacement for the original raw CSVs.
