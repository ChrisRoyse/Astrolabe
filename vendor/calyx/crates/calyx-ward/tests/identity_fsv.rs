#![cfg(feature = "onnx-lens")] // #191: ONNX ml-lens tests only build with the feature
#[path = "identity_fsv/speaker_similarity.rs"]
mod speaker_similarity;

#[path = "identity_fsv/style_quarantine.rs"]
mod style_quarantine;

#[path = "identity_fsv/voxceleb_identity.rs"]
mod voxceleb_identity;
