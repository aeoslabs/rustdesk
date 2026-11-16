// Generates the peer-to-peer message types from RustDesk's own message.proto,
// so vv-term needs only hbb_common and not the full rustdesk crate.
fn main() {
    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());
    std::fs::create_dir_all(&out_dir).unwrap();
    println!("cargo:rerun-if-changed=../libs/base/protos/message.proto");
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["../libs/base/protos/message.proto"])
        .include("../libs/base/protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");
}
