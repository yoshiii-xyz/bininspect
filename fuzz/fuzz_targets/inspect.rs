#![no_main]

use bininspect::{inspect_bytes, render_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = inspect_bytes("fuzz-input", data);
    let _ = render_json(&report);
});
