//! Names and logical paths: whatever is accepted must be a safe, normalized path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rostdav_core::{LogicalPath, Name};

fuzz_target!(|raw: &str| {
    if let Ok(n) = Name::parse(raw) {
        let s = n.as_str();
        assert!(!s.is_empty() && s != "." && s != "..");
        assert!(!s.chars().any(|c| c == '/' || c == '\\' || c.is_control()));
    }
    if let Ok(p) = LogicalPath::from_url_path(raw) {
        for seg in p.segments() {
            assert!(Name::parse(seg.as_str()).is_ok(), "segment {:?}", seg.as_str());
        }
        assert_eq!(p.is_root(), p.segments().is_empty());
    }
});
