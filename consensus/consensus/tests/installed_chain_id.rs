//! G3 FX-6: QC signing and verification use the chain id INSTALLED at boot.
//! Its own test binary, because the installed id is set once per process.
//! (Written by the S0b adversarial reviewer.)
#[test]
fn the_installed_chain_id_governs_qcs() {
    std::env::set_var("AINCORE_CHAIN_ID", blockchain::DEFAULT_CHAIN_ID);
    blockchain::set_vertex_domain("AINCORE-LOCALTEST-4V-HEAD", "deadbeef");
    assert_eq!(
        consensus::qc::expected_chain_id(),
        "AINCORE-LOCALTEST-4V-HEAD"
    );
}
