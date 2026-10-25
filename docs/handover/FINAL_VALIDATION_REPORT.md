# Final CNN Validation & Handover Report

**Project:** SIH26237 — Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution  
**Component:** Invisible forensic watermarking and CNN watermark detection  
**Report date:** 17 October 2026

## 1. Scope and evidence available

This report summarizes results recorded during the project work. The current handover workspace did not contain the original independent-test CSV files or the complete CNN test scripts, so the values below are an evidence summary from previously recorded test outputs, not a fresh execution. The raw rows have not been reconstructed or fabricated.

## 2. Watermarking component

- PDF watermark embedding and extraction round-trip tests were reported as passing on baseline samples.
- Image watermark embedding and extraction round-trip tests were reported as passing on baseline samples.
- Watermark IDs and confidence values were successfully recovered in clean/baseline tests.
- Exact image watermark ID recovery was not reliable under all severe transformations. Previously recorded failures included heavy JPEG compression, very small resizing, strong blur, and screenshot-like transformations.
- Simulated PDF rasterization/print-scan tests did not consistently recover the exact original ID. These were simulations, not physical print-scan trials.

**Interpretation:** baseline functionality has been demonstrated; robust exact extraction under severe degradation remains a limitation.

## 3. CNN robustness test on generated validation data

Previously recorded `test_cnn_robustness.py` output reported 100% classification accuracy for the generated validation set under each of these conditions:

- Clean images
- JPEG quality 90, 70, 50, and 30
- Resize to 75% and 50%
- Gaussian blur radius 1.0 and 2.0
- Screenshot-like resize plus JPEG compression

**Important limitation:** the validation dataset was generated from only three source images (100 normal and 100 watermarked samples). These 200 generated files are not equivalent to 200 unique real-world source images. Therefore, the reported 100% should be described as performance on this generated validation set, not as proven real-world/generalization accuracy.

## 4. Previously recorded independent-pair threshold analyses

Threshold means a prediction is called watermarked when the CNN's output probability is greater than or equal to the threshold. False positives are clean images classified as watermarked. Detection rate is the fraction of marked images classified as watermarked.

### Dataset A — 26 image pairs

| Threshold | Clean false positives | Watermarked detected |
|---:|---:|---:|
| 0.50 | 6/26 (23.1%) | 26/26 (100%) |
| 0.60 | 5/26 (19.2%) | 25/26 (96.2%) |
| 0.70 | 3/26 (11.5%) | 21/26 (80.8%) |
| 0.80 | 2/26 (7.7%) | 19/26 (73.1%) |
| 0.90 | 0/26 (0%) | 13/26 (50.0%) |

An exploratory threshold of approximately 0.6224 was selected on this same set and produced approximately 92.31% balanced accuracy. Because the threshold was selected using the same data being evaluated, it must not be presented as independently validated.

### Dataset B — 16 image pairs

| Threshold | Clean false positives | Watermarked detected |
|---:|---:|---:|
| 0.50 | 4/16 (25.0%) | 16/16 (100%) |
| 0.60 | 3/16 (18.8%) | 16/16 (100%) |
| 0.70 | 2/16 (12.5%) | 15/16 (93.8%) |
| 0.80 | 1/16 (6.3%) | 14/16 (87.5%) |
| 0.90 | 0/16 (0%) | 10/16 (62.5%) |

### Dataset C — 12 image pairs

| Threshold | Clean false positives | Watermarked detected |
|---:|---:|---:|
| 0.50 | 0/12 (0%) | 12/12 (100%) |
| 0.60 | 0/12 (0%) | 11/12 (91.7%) |
| 0.70 | 0/12 (0%) | 11/12 (91.7%) |
| 0.80 | 0/12 (0%) | 9/12 (75.0%) |
| 0.90 | 0/12 (0%) | 6/12 (50.0%) |

These are separate recorded analyses and should not be pooled as if they were one clean benchmark. The datasets are small, and some supposedly external test images overlap with the training-source collection. Pixel-exact overlap checks do not detect every resized or recompressed duplicate.

## 5. Required next validation for stronger claims

1. Gather a fresh set of source images not used for training, validation, threshold selection, or prior test runs.
2. Keep source-level separation; never put transformed versions of the same original image into both training and evaluation.
3. Evaluate normal and watermarked versions of each same source image as matched pairs.
4. Select a threshold on a calibration set, then freeze it before evaluating on the final held-out set.
5. Report confusion matrix, false-positive rate, recall, precision, and sample counts.
6. Test watermark extraction separately from CNN classification. A CNN positive result does not prove the original watermark ID was recovered.
7. Do not regenerate the current dataset without a backup: the dataset generator deletes and recreates `cnn_dataset`.

## 6. Handover status

The implementation and recorded tests are substantially complete. The existing checkpoint should be preserved. The handover archive prepared in this workspace does not contain the latest independent-test CSV files or all of the CNN training/evaluation scripts because they were not present in the available workspace when packaging. Copy those files from the project machine into the archive if the team requires the raw artifacts.

## Suggested presentation wording

> I implemented PDF and image watermark embedding/extraction and a CNN-based detector. Baseline watermark round-trip tests passed, and the CNN scored 100% on our generated validation set under the tested degradations. Independent paired-image evaluations exposed a false-positive/recall trade-off, and some test sources overlap with training sources, so I am not claiming the generated validation score proves generalization to unseen real-world images. Exact watermark extraction can also fail under severe image degradation.
