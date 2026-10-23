//! `Range` header and the request / `Destination` paths of every URL space.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, u64)| {
    rostdav_dav::fuzzing::range(input.0, input.1);
    rostdav_dav::fuzzing::targets(input.0);
});
