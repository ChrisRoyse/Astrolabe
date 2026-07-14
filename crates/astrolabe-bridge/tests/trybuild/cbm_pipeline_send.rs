fn main() {
    let pipeline = astrolabe_bridge::CbmPipeline::new(
        ".",
        ":memory:",
        astrolabe_bridge::CbmIndexMode::Fast,
    )
    .unwrap();
    std::thread::spawn(move || drop(pipeline));
}
