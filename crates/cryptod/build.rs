//! Build script to generate protobuf code using prost.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell cargo to rerun if proto file changes
    println!("cargo:rerun-if-changed=../../proto/crypto_api.proto");

    // Configure prost-build
    let mut config = prost_build::Config::new();
    
    // Use BTreeMap for deterministic ordering
    config.btree_map(["."]);
    
    // Generate code
    config.compile_protos(
        &["../../proto/crypto_api.proto"],
        &["../../proto/"],
    )?;

    Ok(())
}
