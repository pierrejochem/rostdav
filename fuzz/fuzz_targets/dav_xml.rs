//! WebDAV request bodies (PROPFIND, PROPPATCH, REPORT).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    rostdav_dav::fuzzing::xml_bodies(body);
});
