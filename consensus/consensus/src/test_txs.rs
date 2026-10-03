//! Valid payload items for tests. Vertex ingress refuses a vertex whose
//! payload is not made of well-formed, signed transactions (B12), so a test
//! payload must be real transactions.

/// A small signed transaction, distinct per (seed, sequence number).
pub(crate) fn tx(chain_id: &str, seed: u8, sequence_number: u64) -> String {
    executor::admission::signed_publish([seed; 32], chain_id, sequence_number, vec![seed])
}

/// A signed transaction that carries `tag`: distinct tags, distinct items.
pub(crate) fn tagged(chain_id: &str, tag: &str) -> String {
    executor::admission::signed_publish([7; 32], chain_id, 0, tag.as_bytes().to_vec())
}

/// Signed transactions whose JSON array is exactly `bytes` longer than `[]`,
/// so a vertex can be built to an exact size.
pub(crate) fn payload_of_size(chain_id: &str, seed: u8, bytes: usize) -> Vec<String> {
    let json_len = |item: &String| serde_json::to_string(item).unwrap().len();
    let make = |seq: u64, module_len: usize| {
        executor::admission::signed_publish([seed; 32], chain_id, seq, vec![seed; module_len])
    };
    let smallest = json_len(&make(0, 0));
    let mut items: Vec<String> = Vec::new();
    let mut used = 0usize; // the items' bytes plus the commas between them
    loop {
        let comma = usize::from(!items.is_empty());
        let left = bytes
            .checked_sub(used + comma)
            .expect("no room for one more transaction");
        // A full transaction (~80 KB), if one fits with room for a last one.
        let full = make(items.len() as u64, 40_000);
        if json_len(&full) + 1 + smallest + 64 <= left {
            used += comma + json_len(&full);
            items.push(full);
            continue;
        }
        assert!(left >= smallest, "{bytes} bytes cannot hold a transaction");
        // The last one: each module byte adds two hex characters, a longer
        // sequence number one character.
        let estimate = (left - smallest) / 2;
        for seq in [
            items.len() as u64,
            10 + items.len() as u64,
            100 + items.len() as u64,
        ] {
            for m in estimate.saturating_sub(4)..=estimate + 4 {
                let last = make(seq, m);
                if json_len(&last) == left {
                    items.push(last);
                    assert_eq!(serde_json::to_string(&items).unwrap().len(), bytes + 2);
                    return items;
                }
            }
        }
        panic!("no transaction of exactly {left} JSON bytes");
    }
}
