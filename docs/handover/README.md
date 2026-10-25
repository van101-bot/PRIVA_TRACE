# SIH26237 — Watermarking & CNN Handover

This bundle collects the watermarking implementation and supporting test scripts available in the current workspace for handover.

## Contents
- `src/`: image watermarking, PDF watermarking, QKD helper, and CNN model definition.
- `tests/`: watermarking tests, robustness tests, quality metrics, and run helpers available in the workspace.
- `model/watermark_cnn.pth`: available CNN checkpoint, if included.
- `test_assets/`: sample source and watermarked files available in the workspace.
- `docs/`: project notes, final validation report, and handover checklist.
- `reports/cnn_threshold_summary.csv`: aggregate historical threshold results (not raw per-image predictions).

## Important notes
- This is a handover bundle assembled from files available in the current ChatGPT workspace; it may not include the latest scripts or CSV reports from the full Windows/WSL project directory.
- The CNN checkpoint is provided as an artifact; training was not rerun while preparing this ZIP.
- Do not run any dataset-generation script without reviewing it first, because the original generator deletes and recreates `cnn_dataset`.
- Previous testing showed that exact watermark extraction can fail under severe compression, resizing, blur, or screenshot-like transformations.
- CNN validation on generated samples does not by itself prove generalization to unseen source images. Some existing test collections overlap with training sources.

## Suggested handover checks
1. Confirm the checkpoint and source files match the versions in the team's main repository.
2. Include the latest independent test CSVs and full logs from the project machine if they are required for final submission.
3. Run tests in a separate copy of the project and preserve existing datasets/checkpoints.
