// SPDX-License-Identifier: GPL-3.0-or-later

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    // SAFETY: build scripts run in their own process. Setting PROTOC here only
    // selects the checked-in build dependency for this invocation.
    unsafe { std::env::set_var("PROTOC", protoc) };

    tonic_prost_build::compile_protos("proto/boring_logtail/v1/logs.proto")?;
    println!("cargo:rerun-if-changed=proto/boring_logtail/v1/logs.proto");

    Ok(())
}
