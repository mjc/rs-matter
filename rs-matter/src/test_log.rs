/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::ThreadId;

use log::{LevelFilter, Log, Metadata, Record};

static LOGGER: TestLogger = TestLogger;
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());
static LOGGER_INSTALLED: OnceLock<()> = OnceLock::new();
static CAPTURE_THREAD: OnceLock<Mutex<Option<ThreadId>>> = OnceLock::new();
static CAPTURED_LOGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

struct TestLogger;

impl Log for TestLogger {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        if CAPTURE_THREAD
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap()
            .as_ref()
            == Some(&std::thread::current().id())
        {
            CAPTURED_LOGS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap()
                .push(format!("{}", record.args()));
        }
    }

    fn flush(&self) {}
}

struct ResetCapture {
    _lock: MutexGuard<'static, ()>,
}

impl Drop for ResetCapture {
    fn drop(&mut self) {
        *CAPTURE_THREAD
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = None;
    }
}

pub(crate) fn init() {
    LOGGER_INSTALLED.get_or_init(|| {
        log::set_logger(&LOGGER).expect("no test logger was installed before log capture")
    });
}

pub(crate) fn capture(level: LevelFilter, f: impl FnOnce()) -> Vec<String> {
    let guard = CAPTURE_LOCK.lock().unwrap();
    init();
    log::set_max_level(level);

    let logs = CAPTURED_LOGS.get_or_init(|| Mutex::new(Vec::new()));
    logs.lock().unwrap().clear();
    *CAPTURE_THREAD
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = Some(std::thread::current().id());
    let _reset = ResetCapture { _lock: guard };

    f();

    logs.lock().unwrap().clone()
}
