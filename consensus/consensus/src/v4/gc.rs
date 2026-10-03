//! G1 S7: what the engine does when the GC floor g rises (GC-1..GC-5, OR-3 of
//! `docs/G1_CONSENSUS_CONTRACT.md`). g is a function of the committed prefix
//! (the ordering engine persists it with each accepted anchor), so every
//! honest node settles, forgets and deletes the same things.

use super::*;

impl Engine {
    /// Act on a risen floor: OR-3, retire what is now settled, and GC-3.
    pub(super) fn observe_floor(&mut self, net: &dyn ConsensusNet) {
        let g = self.gc_floor();
        if g <= self.last_floor {
            return;
        }
        self.last_floor = g;
        // OR-3: every waiting child is re-evaluated; a parent at or below g is
        // settled now. Children still missing a parent register again.
        let children: Vec<String> = std::mem::take(&mut self.waiting)
            .into_values()
            .flatten()
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();
        for child in children {
            self.try_orderable(child);
        }
        // RE-4: a want at or below g retires; a PENDING vertex at or below g
        // is stale (IN-1 E3).
        self.body_wants.retain(|_, w| w.round > g);
        self.cert_wants.retain(|(r, _), _| *r > g);
        let keep: Vec<Vertex> = self
            .pending
            .take_all()
            .into_iter()
            .filter(|v| v.round > g)
            .collect();
        for v in keep {
            self.pending.push(v);
        }
        self.collect_garbage(g.saturating_sub(staging::RETAIN_SLACK), net);
    }

    /// GC-3: delete every row of this epoch at or below `cut`, and forget it
    /// in memory. Guards below g are safe to delete: IN-1 refuses (STALE)
    /// any vertex at or below g, so nothing there is ever signed again.
    /// Epoch, committee, guard-origin and floor rows are never deleted.
    fn collect_garbage(&mut self, cut: u64, _net: &dyn ConsensusNet) {
        if cut == 0 {
            return;
        }
        if !self.delete_epoch_rows(self.epoch, cut) {
            return; // retried at the next rise of the floor
        }
        self.forget_below(cut);
    }

    /// Delete `epoch`'s staged bodies, slot rows, certificates, this node's
    /// guards and producer guards at rounds at or below `cut`, and give the
    /// plain-body budget back, in one transaction. True when committed.
    pub(super) fn delete_epoch_rows(&self, epoch: u64, cut: u64) -> bool {
        let cg = vcert::chain_genesis_tag(&self.cfg.chain_id, &self.cfg.genesis_identity);
        let bls_pk = hex::encode(
            BLSEngine::consensus().pubkey_raw(&qc::derive_validator_bls_seed(&self.cfg.node_key)),
        );
        let slots = format!("consensus:vslot:v1:{epoch:020}:");
        let certs = format!("consensus:vcert:v1:{epoch:020}:");
        let guards = format!("consensus:vattest:v1:{cg}:{bls_pk}:{epoch}:");
        let proposed = format!("consensus:vproposed:v1:{cg}:{}:{epoch}:", self.ed25519_pk);
        let round_of = |key: &[u8], prefix: &str, at_end: bool| -> Option<u64> {
            let rest = std::str::from_utf8(key.get(prefix.len()..)?).ok()?;
            let field = if at_end {
                rest.rsplit(':').next()?
            } else {
                rest.split(':').next()?
            };
            field.parse().ok()
        };
        let mut doomed: Vec<Vec<u8>> = Vec::new();
        let mut freed: HashMap<String, u64> = HashMap::new();
        for row in self.storage.db.prefix_iterator(slots.as_bytes()) {
            let Ok((key, value)) = row else { break };
            if !key.starts_with(slots.as_bytes()) {
                break;
            }
            match round_of(&key, &slots, false) {
                Some(r) if r <= cut => {
                    let author = std::str::from_utf8(&key)
                        .ok()
                        .and_then(|k| k.rsplit(':').next())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(entries) = serde_json::from_slice::<Vec<staging::SlotEntry>>(&value) {
                        for e in entries {
                            if e.role == Role::Staged {
                                *freed.entry(author.clone()).or_insert(0) += e.bytes;
                            }
                            doomed.push(format!("vertex:{}", e.digest).into_bytes());
                        }
                    }
                    doomed.push(key.to_vec());
                }
                _ => break, // rows are in round order
            }
        }
        for (prefix, at_end) in [(&certs, false), (&proposed, true), (&guards, true)] {
            for row in self.storage.db.prefix_iterator(prefix.as_bytes()) {
                let Ok((key, _)) = row else { break };
                if !key.starts_with(prefix.as_bytes()) {
                    break;
                }
                if round_of(&key, prefix, at_end).is_some_and(|r| r <= cut) {
                    doomed.push(key.to_vec());
                } else if !at_end {
                    break; // round-ordered keys
                }
            }
        }
        let result = self.storage.transaction(|view| {
            for key in &doomed {
                let key = std::str::from_utf8(key).map_err(storage_err)?;
                view.delete(key).map_err(storage_err)?;
            }
            // The plain-body budget gives back what GC removed (ST-3).
            for (author, bytes) in &freed {
                let key = staging::vbytes_key(epoch, author);
                let held = view
                    .get(&key)
                    .map_err(storage_err)?
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                view.put(&key, &held.saturating_sub(*bytes).to_string())
                    .map_err(storage_err)?;
            }
            Ok(())
        });
        result.is_ok()
    }

    /// Forget in memory what GC deleted at or below `cut`.
    fn forget_below(&mut self, cut: u64) {
        {
            let mut dag = lock(&self.dag);
            dag.retain(|_, v| v.round > cut);
            let mut index = lock(&self.round_index);
            index.retain(|r, _| *r > cut);
            self.orderable.retain(|d| dag.contains_key(d));
        }
        self.certs.retain(|(r, _), _| *r > cut);
        self.cert_stake.retain(|r, _| *r > cut);
        self.quorum_since.retain(|r, _| *r > cut);
        self.owed_at.retain(|r, _| *r > cut);
        self.own.retain(|r, _| *r > cut);
        self.collectors.retain(|r, _| *r > cut);
    }
}
