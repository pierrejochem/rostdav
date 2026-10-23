//! Names that clients choose and the server turns into file names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rostdav_storage::{BlobId, ChunkName};

fuzz_target!(|raw: &str| {
    if let Ok(c) = ChunkName::parse(raw) {
        let s = c.as_str();
        assert!(!s.contains(['/', '\\', '\0']) && s != "." && s != "..");
    }
    if let Ok(b) = BlobId::parse(raw) {
        assert!(!b.as_str().contains(['/', '\\', '\0', '.']));
    }
});
