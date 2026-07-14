fn main() {
    let runner = astrolabe_bridge::CbmToolRunner::new(":memory:").unwrap();
    std::thread::spawn(move || drop(runner));
}
