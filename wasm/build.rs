use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir: PathBuf = ["..", "protos"].iter().collect();
    let proto_files = [
        proto_dir.join("peer_rpc.proto"),
        proto_dir.join("common.proto"),
        proto_dir.join("error.proto"),
    ];

    for proto in &proto_files {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // Cloudflare's build image is intentionally minimal; use a pinned, vendored
    // protoc instead of relying on an operating-system package.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let protoc_include = protoc_bin_vendored::include_path()?;
    unsafe { std::env::set_var("PROTOC", protoc) };

    let mut config = prost_build::Config::new();
    config
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(".common", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".error", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".peer_rpc", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("peer_rpc.DirectConnectedPeerInfo", "#[derive(Hash)]")
        .type_attribute("peer_rpc.PeerInfoForGlobalMap", "#[derive(Hash)]")
        .type_attribute("peer_rpc.ForeignNetworkRouteInfoKey", "#[derive(Hash, Eq)]")
        .extern_path(".google.protobuf.Timestamp", "crate::proto::Timestamp")
        .btree_map(["."]);

    config.compile_protos(&proto_files, &[proto_dir, protoc_include])?;
    Ok(())
}
