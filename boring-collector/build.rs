// SPDX-License-Identifier: GPL-3.0-or-later

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    // SAFETY: build scripts run in their own process. Setting PROTOC here only
    // selects the checked-in build dependency for this invocation.
    unsafe { std::env::set_var("PROTOC", protoc) };

    tonic_prost_build::compile_protos("proto/boring_logtail/v1/logs.proto")?;
    println!("cargo:rerun-if-changed=proto/boring_logtail/v1/logs.proto");

    let source = std::path::PathBuf::from("proto/otlp");
    let protos = [
        source.join("opentelemetry/proto/collector/logs/v1/logs_service.proto"),
        source.join("opentelemetry/proto/collector/metrics/v1/metrics_service.proto"),
    ];
    let descriptor =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("otlp_descriptor.bin");
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .file_descriptor_set_path(descriptor)
        .compile_protos(&protos, &[source])?;

    Ok(())
}
