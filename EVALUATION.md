# External evaluation protocol

The included generated fixtures are regression tests. Do not cite their accuracy as camera or modern-generator detection accuracy.

1. Assemble independently sourced real photographs, localized manipulations, and actual generator outputs. Record source URLs, licenses, consent/usage constraints, labels, camera/generator versions, and transformations in a manifest kept with the dataset.
2. Split by original scene/source image, camera collection, and generator family before selecting thresholds. Keep derivatives of one original in the same split. Check exact hashes and perceptual duplicates across splits, and document possible overlap with pretrained model training data.
3. Freeze model revisions, preprocessing, thresholds, and fusion rules using training/development data. Keep the final test split sealed during tuning.
4. Run the evaluator separately on originals, JPEG quality 75, and 50% resizing. Its binary metric uses authentic as positive: false positives are forged/synthetic inputs accepted as authentic. Keep tampered and synthetic cohorts separate.
5. Report class counts, confusion matrices, precision/recall, exact rank AUC, confidence intervals, abstention/uncertain cases, per-source failures, latency and hardware. Do not imply a probability interpretation until a separate calibration set and reliability metrics justify it.
6. Compare against individual branches and the neural backbone before crediting fusion. Evaluate local manipulation maps against independently labelled masks before claiming localization accuracy. Pixel-change percentage is not IoU.
7. Publish reproducible commands, dataset hashes and permissible example images. A folder label alone does not establish trustworthy ground truth. The evaluator does not audit dataset independence for you.

A successful real-world evaluation remains outstanding. The CLI and reports support collecting the evidence; this repository does not manufacture that evidence.
