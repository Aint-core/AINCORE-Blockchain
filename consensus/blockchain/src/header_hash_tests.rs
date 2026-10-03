//! G3 FX-18: the canonical block header hash and body roots.
//!
//! Each boundary test builds two headers that the legacy preimage hashed
//! identically, checks that they really did collide there, and checks that
//! they no longer do. The legacy check keeps each test honest: a pair that
//! never collided would prove nothing about the boundary it names.

use super::*;

/// The pre-FX-18 header hash, verbatim. Kept only to prove each pair below
/// was a real collision.
fn legacy_header_hash(header: &BlockHeader) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(header.height.to_string().as_bytes());
    data.extend_from_slice(header.prev_hash.as_bytes());
    data.extend_from_slice(header.tx_hash.as_bytes());
    if !header.state_root.is_empty() || !header.receipts_root.is_empty() {
        data.extend_from_slice(header.state_root.as_bytes());
        data.extend_from_slice(header.receipts_root.as_bytes());
    }
    data.extend_from_slice(header.proposer_id.as_bytes());
    data.extend_from_slice(header.round.to_string().as_bytes());
    data.extend_from_slice(header.timestamp.to_string().as_bytes());
    if !header.vertices_root.is_empty() {
        data.extend_from_slice(header.vertices_root.as_bytes());
    }
    if !header.evidence_root.is_empty() {
        data.extend_from_slice(header.evidence_root.as_bytes());
    }
    hex::encode(hash(&data))
}

fn legacy_tx_hash(transactions: &[String]) -> String {
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(tx.as_bytes());
    }
    hex::encode(hash(&data))
}

fn legacy_vertices_root(vertices: &[String]) -> String {
    if vertices.is_empty() {
        return String::new();
    }
    let mut data = Vec::new();
    data.extend_from_slice((vertices.len() as u64).to_be_bytes().as_slice());
    for v in vertices {
        data.extend_from_slice(v.as_bytes());
    }
    hex::encode(hash(&data))
}

fn header() -> BlockHeader {
    BlockHeader {
        height: 7,
        prev_hash: "11".repeat(32),
        tx_hash: "22".repeat(32),
        state_root: "33".repeat(32),
        receipts_root: "44".repeat(32),
        vertices_root: "55".repeat(32),
        evidence_root: "66".repeat(32),
        da_root: "88".repeat(32),
        proposer_id: "77".repeat(32),
        round: 20,
        timestamp: 1_790_667_886,
        hash: String::new(),
    }
}

/// `a` and `b` collided under the legacy preimage and must not now.
fn assert_split(a: &BlockHeader, b: &BlockHeader, boundary: &str) {
    assert_eq!(
        legacy_header_hash(a),
        legacy_header_hash(b),
        "{boundary}: the pair must be a real legacy collision"
    );
    assert_ne!(
        calculate_header_hash(a),
        calculate_header_hash(b),
        "{boundary}: two different headers still share a hash"
    );
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------- golden

/// Pins the format. The expected bytes were produced independently of this
/// crate from the written layout, so a change of any byte of the encoding
/// (field order, width, endianness, tag or domain) fails here.
#[test]
fn golden_header_preimage_and_hash() {
    let mut h = header();
    h.prev_hash = "p".into();
    h.tx_hash = "t".into();
    h.state_root = "s".into();
    h.receipts_root = String::new();
    h.vertices_root = "v".into();
    h.evidence_root = String::new();
    h.da_root = "d".into();
    h.proposer_id = "q".into();
    h.hash = "ignored: the hash field is not part of its own preimage".into();
    let expected = concat!(
        "41494e434f52455f424c4f434b5f4845414445525f563200", // AINCORE_BLOCK_HEADER_V2\0
        "0700000000000000",                                 // height 7
        "010000000000000070",                               // prev_hash "p"
        "010000000000000074",                               // tx_hash "t"
        "01010000000000000073",                             // state_root present "s"
        "00",                                               // receipts_root absent
        "01010000000000000076",                             // vertices_root present "v"
        "00",                                               // evidence_root absent
        "010000000000000064",                               // da_root "d"
        "010000000000000071",                               // proposer_id "q"
        "1400000000000000",                                 // round 20
        "6e6cbb6a00000000",                                 // timestamp 1790667886
    );
    assert_eq!(hex::encode(header_preimage(&h)), expected);
    assert_eq!(
        calculate_header_hash(&h),
        "2575ef6d6c2034d78d84b6ca27b9b56e5f5e3d77dcfbffdd7402fd6914e1b22a"
    );
}

/// A realistic header: 64-hex fields, every root present.
#[test]
fn golden_header_hash_full() {
    assert_eq!(
        calculate_header_hash(&header()),
        "104c53635334a229b920d81fea16684aaffbe5785ef951d52408626d8942db74"
    );
}

#[test]
fn golden_body_roots() {
    let items = strings(&["a", "bc"]);
    assert_eq!(
        calculate_tx_hash(&items),
        "fbcb4168190b419f23ae5e6ffc28992955d1777134eac0566040a053811014d3"
    );
    assert_eq!(
        calculate_tx_hash(&[]),
        "3c12570c42a0ac8980a8454a463f371964af5861c30fdc21d07f979d1824669d"
    );
    // B4: the sequence with its authors, under AINCORE_BLOCK_SEQUENCE_V1
    // (independent Python encoder; it reproduces the V1 value b87b41ea...).
    assert_eq!(
        calculate_vertices_root(&items, &strings(&["x", "y"])),
        "76c3cbca4b6d8b45041d168003524a24c0d2674d1f5a21370b0bd67cf01826e2"
    );
    assert_eq!(
        calculate_evidence_root(&items),
        "f7cd4f77edbd5d1cc07c26f92e9e745c6bbe451aad2cb21e03d411b950fdde3b"
    );
}

/// B1: the body preimage, and its DA root from `da/reference/da_ref.py`.
/// B4 added the authors list and moved the domain to V2 (the reference
/// reproduces the V1 root 261be831... and gives 23e279db... here).
#[test]
fn golden_body_bytes_and_da_root() {
    let body = body_bytes(
        &strings(&["a", "bc"]),
        &strings(&["v"]),
        &strings(&["w"]),
        "v",
        &[],
    );
    let expected = concat!(
        "41494e434f52455f424c4f434b5f424f44595f563200", // AINCORE_BLOCK_BODY_V2\0
        "0200000000000000",                             // 2 transactions
        "010000000000000061",                           // "a"
        "02000000000000006263",                         // "bc"
        "0100000000000000",                             // 1 committed vertex
        "010000000000000076",                           // "v"
        "0100000000000000",                             // 1 author (B4)
        "010000000000000077",                           // "w"
        "010000000000000076",                           // anchor_hash "v"
        "0000000000000000",                             // no slash evidence
    );
    assert_eq!(hex::encode(&body), expected);
    assert_eq!(
        da::da_root(&body),
        "23e279db90eb1c13c437f8fa3a583745415593d64b73e18d86bb7ca37a45f438"
    );
}

fn block() -> Block {
    Block::new_with_roots_at(
        7,
        20,
        "11".repeat(32),
        strings(&["tx1", "tx2"]),
        "77".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        1_790_667_886,
        strings(&["v1", "v2"]),
        strings(&["a1", "a2"]),
        "v2".into(),
        strings(&["e1"]),
    )
}

/// The header binds every body field, `anchor_hash` included (B1), and
/// `check_commitments` finds every mismatch.
#[test]
fn check_commitments_binds_every_body_field() {
    let b = block();
    assert_eq!(b.check_commitments(), Ok(()), "control");
    assert_eq!(b.header.da_root, da::da_root(&b.body_bytes()));

    type Edit = fn(&mut Block);
    let edits: [(&str, Edit, &str); 8] = [
        (
            "transactions",
            |b| b.transactions.push("tx3".into()),
            "Transaction hash mismatch",
        ),
        (
            "committed_vertices",
            |b| b.committed_vertices.reverse(),
            "Vertices root mismatch",
        ),
        (
            "committed_authors",
            |b| b.committed_authors.reverse(),
            "Vertices root mismatch",
        ),
        (
            "an author too few",
            |b| {
                b.committed_authors.pop();
            },
            "Vertices root mismatch",
        ),
        (
            "slash_evidence",
            |b| b.slash_evidence.clear(),
            "Evidence root mismatch",
        ),
        (
            "anchor_hash",
            |b| b.anchor_hash = "v1".into(),
            "DA root mismatch",
        ),
        (
            "a header field",
            |b| b.header.round = 21,
            "Hash Mismatch",
        ),
        (
            "da_root",
            |b| b.header.da_root = "00".repeat(32),
            "Hash Mismatch",
        ),
    ];
    for (name, edit, expected) in edits {
        let mut t = b.clone();
        edit(&mut t);
        let err = t.check_commitments().expect_err(name);
        assert!(err.starts_with(expected), "{name}: {err}");
    }

    // Re-hashing the header after a body edit still fails on the root that
    // binds the edited field: the body cannot be swapped under a fresh hash.
    let mut t = b.clone();
    t.anchor_hash = "v1".into();
    t.header.hash = calculate_header_hash(&t.header);
    assert!(t
        .check_commitments()
        .unwrap_err()
        .starts_with("DA root mismatch"));

    // Changing anchor_hash alone changes the block hash.
    let rebuilt = Block::new_with_roots_at(
        7,
        20,
        "11".repeat(32),
        strings(&["tx1", "tx2"]),
        "77".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        1_790_667_886,
        strings(&["v1", "v2"]),
        strings(&["a1", "a2"]),
        "v1".into(),
        strings(&["e1"]),
    );
    assert_ne!(rebuilt.header.hash, b.header.hash);
    assert_eq!(rebuilt.check_commitments(), Ok(()));
}

/// An empty vertex sequence or evidence list is an absent root, which the
/// header encodes with the absent tag (sync relies on "" meaning "none").
#[test]
fn empty_vertices_and_evidence_are_absent_roots() {
    assert_eq!(calculate_vertices_root(&[], &[]), "");
    assert_eq!(calculate_evidence_root(&[]), "");
    assert_ne!(
        calculate_vertices_root(&strings(&[""]), &strings(&[""])),
        ""
    );
    assert_ne!(calculate_evidence_root(&strings(&[""])), "");
}

// ------------------------------------------------------------ framing

/// Reads a header back out of its preimage, following the written layout and
/// nothing else. A preimage that parses back into exactly its header cannot
/// be shared by two headers: this is injectivity in executable form.
fn parse_preimage(bytes: &[u8]) -> Option<BlockHeader> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn str(&mut self) -> Option<String> {
            let len = usize::try_from(self.u64()?).ok()?;
            String::from_utf8(self.take(len)?.to_vec()).ok()
        }
        fn opt_root(&mut self) -> Option<String> {
            match self.take(1)?[0] {
                0 => Some(String::new()),
                1 => self.str().filter(|root| !root.is_empty()),
                _ => None,
            }
        }
    }
    let mut r = Reader(bytes.strip_prefix(b"AINCORE_BLOCK_HEADER_V2\0")?);
    // Struct expression fields evaluate in the order written: the layout order.
    let header = BlockHeader {
        height: r.u64()?,
        prev_hash: r.str()?,
        tx_hash: r.str()?,
        state_root: r.opt_root()?,
        receipts_root: r.opt_root()?,
        vertices_root: r.opt_root()?,
        evidence_root: r.opt_root()?,
        da_root: r.str()?,
        proposer_id: r.str()?,
        round: r.u64()?,
        timestamp: r.u64()?,
        hash: String::new(),
    };
    r.0.is_empty().then_some(header)
}

type Fields = (
    u64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    u64,
    u64,
);

fn fields(h: &BlockHeader) -> Fields {
    (
        h.height,
        h.prev_hash.clone(),
        h.tx_hash.clone(),
        h.state_root.clone(),
        h.receipts_root.clone(),
        h.vertices_root.clone(),
        h.evidence_root.clone(),
        h.da_root.clone(),
        h.proposer_id.clone(),
        h.round,
        h.timestamp,
    )
}

/// Every header, including hostile ones (control bytes, fake length prefixes,
/// fake tags, extreme integers, non-ASCII text), parses back from its preimage.
#[test]
fn preimage_parses_back_into_its_header() {
    let fake_prefix = "p\u{9}\0\0\0\0\0\0\0\u{1}";
    let none = String::new;
    let cases = vec![
        header(),
        BlockHeader {
            height: 0,
            prev_hash: none(),
            tx_hash: none(),
            state_root: none(),
            receipts_root: none(),
            vertices_root: none(),
            evidence_root: none(),
            da_root: none(),
            proposer_id: none(),
            round: 0,
            timestamp: 0,
            hash: none(),
        },
        BlockHeader {
            height: u64::MAX,
            round: u64::MAX,
            timestamp: u64::MAX,
            ..header()
        },
        BlockHeader {
            prev_hash: fake_prefix.into(),
            tx_hash: "\u{1}\0\0\0\0\0\0\0Z".into(),
            state_root: "\0".into(),
            receipts_root: "\u{1}".into(),
            vertices_root: none(),
            evidence_root: fake_prefix.into(),
            da_root: "\u{1}".into(),
            proposer_id: "\0\0\0\0\0\0\0\0".into(),
            ..header()
        },
        BlockHeader {
            prev_hash: "é".into(),
            state_root: none(),
            receipts_root: "✓".into(),
            proposer_id: "validator ✓".into(),
            ..header()
        },
    ];
    for h in cases {
        let parsed = parse_preimage(&header_preimage(&h)).expect("the preimage must parse");
        assert_eq!(fields(&parsed), fields(&h));
    }
}

/// Each variable-length field's length prefix is load-bearing. For each field
/// F and the field N after it, header A has F = "p" and N = N's own encoding
/// of "Z"; header B has F = "p" followed by N's framing, and N = "Z". Without
/// F's prefix the two headers are the same bytes; with it they are not.
#[test]
fn a_field_cannot_swallow_its_neighbours_framing() {
    fn le(n: usize) -> Vec<u8> {
        (n as u64).to_le_bytes().to_vec()
    }
    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("control bytes are valid UTF-8")
    }
    fn set(h: &mut BlockHeader, field: usize, value: String) {
        match field {
            0 => h.prev_hash = value,
            1 => h.tx_hash = value,
            2 => h.state_root = value,
            3 => h.receipts_root = value,
            4 => h.vertices_root = value,
            5 => h.evidence_root = value,
            6 => h.da_root = value,
            _ => h.proposer_id = value,
        }
    }
    let is_root = |field: usize| (2..=5).contains(&field);
    for field in 0..7 {
        let next = field + 1;
        // N's encoding of "Z", and the framing N's encoding puts before it.
        let (n_encoding, n_framing) = if is_root(next) {
            let enc = [vec![1], le(1), b"Z".to_vec()].concat();
            let framing = [vec![1], le(enc.len())].concat();
            (enc, framing)
        } else {
            let enc = [le(1), b"Z".to_vec()].concat();
            let framing = le(enc.len());
            (enc, framing)
        };
        let mut a = header();
        set(&mut a, field, "p".into());
        set(&mut a, next, text(n_encoding));
        let mut b = header();
        set(&mut b, field, text([b"p".to_vec(), n_framing].concat()));
        set(&mut b, next, "Z".into());
        assert_ne!(
            calculate_header_hash(&a),
            calculate_header_hash(&b),
            "field {field} swallowed the framing of field {next}"
        );
    }
}

// ------------------------------------------------------ review PoC + boundaries

/// The adversarial review's PoC: round 20 at 1790667886 and round 201 at
/// 790667886 shared one hash.
#[test]
fn review_poc_round_timestamp_pair_now_differs() {
    let a = BlockHeader {
        round: 20,
        timestamp: 1_790_667_886,
        ..header()
    };
    let b = BlockHeader {
        round: 201,
        timestamp: 790_667_886,
        ..header()
    };
    assert_split(&a, &b, "round | timestamp");
}

#[test]
fn boundary_height_prev_hash() {
    let a = BlockHeader {
        height: 1,
        prev_hash: "2ab".into(),
        ..header()
    };
    let b = BlockHeader {
        height: 12,
        prev_hash: "ab".into(),
        ..header()
    };
    assert_split(&a, &b, "height | prev_hash");
}

#[test]
fn boundary_prev_hash_tx_hash() {
    let a = BlockHeader {
        prev_hash: "ab".into(),
        tx_hash: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        prev_hash: "a".into(),
        tx_hash: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "prev_hash | tx_hash");
}

#[test]
fn boundary_tx_hash_state_root() {
    let a = BlockHeader {
        tx_hash: "ab".into(),
        state_root: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        tx_hash: "a".into(),
        state_root: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "tx_hash | state_root");
}

#[test]
fn boundary_state_root_receipts_root() {
    let a = BlockHeader {
        state_root: "ab".into(),
        receipts_root: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        state_root: "a".into(),
        receipts_root: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "state_root | receipts_root");
    // The whole value on either side of the boundary.
    let a = BlockHeader {
        state_root: "abc".into(),
        receipts_root: String::new(),
        ..header()
    };
    let b = BlockHeader {
        state_root: String::new(),
        receipts_root: "abc".into(),
        ..header()
    };
    assert_split(&a, &b, "state_root | receipts_root (moved whole)");
}

#[test]
fn boundary_receipts_root_proposer_id() {
    let a = BlockHeader {
        receipts_root: "ab".into(),
        proposer_id: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        receipts_root: "a".into(),
        proposer_id: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "receipts_root | proposer_id");
}

/// Legacy dropped both execution roots when both were empty, so a prefix of
/// the proposer could pose as a state root.
#[test]
fn boundary_absent_execution_roots() {
    let a = BlockHeader {
        state_root: String::new(),
        receipts_root: String::new(),
        proposer_id: "abc".into(),
        ..header()
    };
    let b = BlockHeader {
        state_root: "a".into(),
        receipts_root: String::new(),
        proposer_id: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "absent execution roots | proposer_id");
}

/// The adversarial review's second example: signer "abc1" at round 23 and
/// "abc" at round 123.
#[test]
fn boundary_proposer_id_round() {
    let a = BlockHeader {
        proposer_id: "abc1".into(),
        round: 23,
        ..header()
    };
    let b = BlockHeader {
        proposer_id: "abc".into(),
        round: 123,
        ..header()
    };
    assert_split(&a, &b, "proposer_id | round");
}

#[test]
fn boundary_timestamp_vertices_root() {
    let a = BlockHeader {
        timestamp: 12,
        vertices_root: "3ab".into(),
        ..header()
    };
    let b = BlockHeader {
        timestamp: 123,
        vertices_root: "ab".into(),
        ..header()
    };
    assert_split(&a, &b, "timestamp | vertices_root");
}

#[test]
fn boundary_vertices_root_evidence_root() {
    let a = BlockHeader {
        vertices_root: "ab".into(),
        evidence_root: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        vertices_root: "a".into(),
        evidence_root: "bc".into(),
        ..header()
    };
    assert_split(&a, &b, "vertices_root | evidence_root");
}

/// Legacy appended whichever tail root was present, so a vertices root and an
/// evidence root with the same value hashed alike.
#[test]
fn boundary_absent_tail_roots() {
    let a = BlockHeader {
        vertices_root: "r".into(),
        evidence_root: String::new(),
        ..header()
    };
    let b = BlockHeader {
        vertices_root: String::new(),
        evidence_root: "r".into(),
        ..header()
    };
    assert_split(&a, &b, "vertices_root present | evidence_root present");
    // A present tail root could also pose as the end of the timestamp.
    let none = String::new;
    let a = BlockHeader {
        timestamp: 12,
        vertices_root: none(),
        evidence_root: none(),
        ..header()
    };
    let b = BlockHeader {
        timestamp: 1,
        vertices_root: "2".into(),
        evidence_root: none(),
        ..header()
    };
    assert_split(&a, &b, "timestamp | absent tail roots");
}

/// The framing must not lean on the values being hex: a root holding the
/// present-tag byte must not re-segment with its neighbour.
#[test]
fn roots_are_length_framed_not_tag_framed() {
    let a = BlockHeader {
        state_root: "a\u{1}b".into(),
        receipts_root: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        state_root: "a".into(),
        receipts_root: "b\u{1}c".into(),
        ..header()
    };
    assert_ne!(calculate_header_hash(&a), calculate_header_hash(&b));
    let a = BlockHeader {
        vertices_root: "a\u{1}b".into(),
        evidence_root: "c".into(),
        ..header()
    };
    let b = BlockHeader {
        vertices_root: "a".into(),
        evidence_root: "b\u{1}c".into(),
        ..header()
    };
    assert_ne!(calculate_header_hash(&a), calculate_header_hash(&b));
}

/// Every field is bound: changing any one of them changes the hash, and the
/// `hash` field itself is excluded.
#[test]
fn every_field_is_bound() {
    let base = header();
    let base_hash = calculate_header_hash(&base);
    let mutants: Vec<(&str, BlockHeader)> = vec![
        (
            "height",
            BlockHeader {
                height: 8,
                ..header()
            },
        ),
        (
            "prev_hash",
            BlockHeader {
                prev_hash: "12".repeat(32),
                ..header()
            },
        ),
        (
            "tx_hash",
            BlockHeader {
                tx_hash: "23".repeat(32),
                ..header()
            },
        ),
        (
            "state_root",
            BlockHeader {
                state_root: "34".repeat(32),
                ..header()
            },
        ),
        (
            "receipts_root",
            BlockHeader {
                receipts_root: "45".repeat(32),
                ..header()
            },
        ),
        (
            "vertices_root",
            BlockHeader {
                vertices_root: "56".repeat(32),
                ..header()
            },
        ),
        (
            "evidence_root",
            BlockHeader {
                evidence_root: "67".repeat(32),
                ..header()
            },
        ),
        (
            "proposer_id",
            BlockHeader {
                proposer_id: "78".repeat(32),
                ..header()
            },
        ),
        (
            "round",
            BlockHeader {
                round: 21,
                ..header()
            },
        ),
        (
            "timestamp",
            BlockHeader {
                timestamp: 1_790_667_887,
                ..header()
            },
        ),
    ];
    for (field, mutant) in mutants {
        assert_ne!(
            calculate_header_hash(&mutant),
            base_hash,
            "{field} is not bound by the hash"
        );
    }
    let rehashed = BlockHeader {
        hash: "anything".into(),
        ..header()
    };
    assert_eq!(
        calculate_header_hash(&rehashed),
        base_hash,
        "hash must not hash itself"
    );
    // Absent differs from present for each optional root.
    for field in [
        "state_root",
        "receipts_root",
        "vertices_root",
        "evidence_root",
    ] {
        let mut h = header();
        match field {
            "state_root" => h.state_root.clear(),
            "receipts_root" => h.receipts_root.clear(),
            "vertices_root" => h.vertices_root.clear(),
            _ => h.evidence_root.clear(),
        }
        assert_ne!(
            calculate_header_hash(&h),
            base_hash,
            "absent {field} is not bound"
        );
    }
}

// ------------------------------------------------------------- body roots

#[test]
fn tx_hash_binds_item_boundaries() {
    let a = strings(&["A", "B"]);
    let b = strings(&["AB"]);
    assert_eq!(
        legacy_tx_hash(&a),
        legacy_tx_hash(&b),
        "a real legacy collision"
    );
    assert_ne!(calculate_tx_hash(&a), calculate_tx_hash(&b));
    // An empty list and a list of one empty transaction.
    assert_eq!(legacy_tx_hash(&[]), legacy_tx_hash(&strings(&[""])));
    assert_ne!(calculate_tx_hash(&[]), calculate_tx_hash(&strings(&[""])));
    assert_ne!(
        calculate_tx_hash(&a),
        calculate_tx_hash(&strings(&["B", "A"])),
        "order is bound"
    );
}

#[test]
fn vertices_root_binds_item_boundaries() {
    let a = strings(&["ab", "c"]);
    let b = strings(&["a", "bc"]);
    assert_eq!(
        legacy_vertices_root(&a),
        legacy_vertices_root(&b),
        "a real legacy collision"
    );
    let none = strings(&["", ""]);
    assert_ne!(
        calculate_vertices_root(&a, &none),
        calculate_vertices_root(&b, &none)
    );
    assert_ne!(
        calculate_vertices_root(&a, &none),
        calculate_vertices_root(&strings(&["c", "ab"]), &none)
    );
    // B4: an author cannot move into the sequence, or across authors.
    assert_ne!(
        calculate_vertices_root(&strings(&["ab"]), &strings(&["c"])),
        calculate_vertices_root(&strings(&["a"]), &strings(&["bc"]))
    );
    assert_ne!(
        calculate_vertices_root(&a, &strings(&["x", "y"])),
        calculate_vertices_root(&a, &strings(&["y", "x"]))
    );
}

#[test]
fn evidence_root_binds_item_boundaries() {
    let a = strings(&["ab", "c"]);
    let b = strings(&["a", "bc"]);
    assert_ne!(calculate_evidence_root(&a), calculate_evidence_root(&b));
    assert_ne!(
        calculate_evidence_root(&a),
        calculate_evidence_root(&strings(&["c", "ab"]))
    );
}

/// A root of one kind can never stand in for another: the same list gives
/// three different roots.
#[test]
fn root_kinds_are_domain_separated() {
    let items = strings(&["x", "y"]);
    let tx = calculate_tx_hash(&items);
    let vertices = calculate_vertices_root(&items, &items);
    let evidence = calculate_evidence_root(&items);
    assert_ne!(tx, vertices);
    assert_ne!(tx, evidence);
    assert_ne!(vertices, evidence);
}

/// End to end: a block built by the constructor carries the canonical roots
/// and hash, and the review's pair built as whole blocks still splits.
#[test]
fn constructed_blocks_use_the_canonical_commitments() {
    let mk = |round, timestamp| {
        Block::new_with_roots_at(
            7,
            round,
            "prev".into(),
            strings(&["tx1", "tx2"]),
            "proposer".into(),
            "s".into(),
            "r".into(),
            timestamp,
            strings(&["v1", "v2"]),
            strings(&["a1", "a2"]),
            "v2".into(),
            strings(&["e1"]),
        )
    };
    let a = mk(20, 1_790_667_886);
    let b = mk(201, 790_667_886);
    assert_eq!(a.header.tx_hash, calculate_tx_hash(&a.transactions));
    assert_eq!(
        a.header.vertices_root,
        calculate_vertices_root(&a.committed_vertices, &a.committed_authors)
    );
    assert_eq!(
        a.header.evidence_root,
        calculate_evidence_root(&a.slash_evidence)
    );
    assert_eq!(a.header.hash, calculate_header_hash(&a.header));
    assert_eq!(legacy_header_hash(&a.header), legacy_header_hash(&b.header));
    assert_ne!(a.header.hash, b.header.hash);
}
