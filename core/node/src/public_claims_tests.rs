//! G5 DOC-1: the public documents make no claim the code contradicts. A lib
//! test, so the release gate (which runs `--lib`) runs it. Each phrase is one
//! a review found false against the code (G5 review, 2026-10-01).

/// (phrase, why it is false). Matched case-insensitively.
const FALSE_CLAIMS: &[(&str, &str)] = &[
    (
        "halving",
        "emission is 1.90 %/yr of the remaining reserve (EM-1)",
    ),
    (
        "slash 5%",
        "downtime is not slashed; equivocation follows SL-4",
    ),
    (
        "5% slash",
        "downtime is not slashed; equivocation follows SL-4",
    ),
    (
        "immediate slash",
        "the fraction settles after D + I x C_tau + W (SL-5)",
    ),
    (
        "genesis supply** | 0",
        "genesis mints the validators' stake and the treasury",
    ),
    (
        "no pre-mine",
        "genesis mints the validators' stake and the treasury",
    ),
    ("1-2 detik", "the V4 block time is not measured yet"),
    ("1-2s", "finality time is not measured yet"),
    ("~10,000", "no TPS is measured"),
    (
        "full block reward",
        "there is no block reward; emission is per period",
    ),
    (
        "block rewards every epoch",
        "rewards are paid every reward period",
    ),
    (
        "fees flow to the treasury",
        "fees are burned 10 %, then 20/80 leader/committee",
    ),
    (
        "mined via depin",
        "DePIN gets no share of emission (DEPIN_BPS = 0)",
    ),
];

#[test]
fn the_public_documents_make_no_claim_the_code_contradicts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for doc in ["README.md", "WHITEPAPER.md", "CLAUDE.md"] {
        let text = std::fs::read_to_string(root.join(doc))
            .unwrap()
            .to_lowercase();
        for (phrase, why) in FALSE_CLAIMS {
            assert!(
                !text.contains(phrase),
                "{doc} still says {phrase:?}, but {why}"
            );
        }
    }
}
