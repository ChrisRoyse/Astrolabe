fn main() {
    let watcher = astrolabe_bridge::CbmWatcher::new_for_polling(|_, _| Ok(())).unwrap();
    std::thread::spawn(move || drop(watcher));
}
