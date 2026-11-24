//! Finality and DAG signing share the RC-3 recovery fence.
use super::*;
use crate::qc_producer::QcVoteMessage;
use std::cell::RefCell;
use std::collections::BTreeMap;

const SEEDS: [u8; 4] = [61, 62, 63, 64];

fn guards(c: &Cluster) -> BTreeMap<String, QcVoteMessage> {
    c.node(0)
        .storage
        .scan_prefix("consensus:qc_signing:")
        .into_iter()
        .map(|(k, v)| (k, serde_json::from_str(&v).unwrap()))
        .collect()
}

fn assert_dag_abstains(c: &Cluster) {
    assert!(!c.node(0).v4_signs());
    for prefix in [
        "consensus:vattest:",
        "consensus:vproposed:",
        "consensus:vproposed_high:",
    ] {
        assert!(
            c.node(0).storage.scan_prefix(prefix).is_empty(),
            "signed {prefix}"
        );
    }
    assert!(c
        .node(0)
        .storage
        .get("consensus:guard_origin")
        .unwrap()
        .is_none());
}

fn recovered(tag: &str) -> Cluster {
    let mut c = Cluster::new(tag, &SEEDS, true);
    c.node(0).storage.delete("consensus:guard_origin").unwrap();
    c.reopen(0);
    assert!(guards(&c).is_empty());
    assert_dag_abstains(&c);
    c
}

#[test]
fn finality_recovery_replays_committed_blocks_while_abstaining() {
    let mut before = Cluster::new("qc-loss-before", &SEEDS, true);
    let wires = RefCell::new(Vec::new());
    for _ in 0..12 {
        for i in 0..4 {
            before.node_mut(i).try_create_vertex();
        }
        before.deliver_filtered(&|from, to, wire| {
            // Record each broadcast once, including this key's old messages.
            if to == usize::from(from == 0) && wire.starts_with("DAG_V4:") {
                wires.borrow_mut().push(wire.to_string());
            }
            false
        });
    }
    let common = before.assert_same_blocks(2);
    let original = guards(&before);
    assert!(!original.is_empty(), "no pre-loss signature to compare");
    assert!(before.qc(0, common).is_some());

    // Fresh genesis state, same member key, no old decisions or signing rows.
    // Feed only real DAG traffic: no peer QC can substitute for local DE-5.
    let mut after = recovered("qc-loss-replay");
    for wire in wires.into_inner() {
        after.node_mut(0).handle_message(&wire);
        after.node_mut(0).try_create_vertex();
    }
    assert!(guards(&after).is_empty(), "replay signed while the guard was unavailable");
    let pending = after.node(0).storage.scan_prefix("consensus:qc_pending:");
    assert!(!pending.is_empty(), "no independent decision reached the finality worker");
    for (_, value) in &pending {
        let work: crate::qc_producer::CommitContext = serde_json::from_str(value).unwrap();
        let height = work.block_height;
        assert!(height > 0 && height <= common);
        assert_eq!(after.block(0, height), before.block(0, height));
        let reference = before.qc(0, height).expect("pre-loss block was certified");
        assert_eq!(work.block_hash, reference.block_hash);
        assert_eq!(work.finality_digest, reference.finality_digest);
        assert_eq!(work.state_root, reference.state_root);
        assert_eq!(work.receipts_root, reference.receipts_root);
    }
    assert_dag_abstains(&after);
    after.reopen(0);
    after.node_mut(0).try_create_vertex();
    assert!(guards(&after).is_empty(), "restart released the recovery fence");
    assert_dag_abstains(&after);
}

#[test]
fn finality_recovery_uncertified_adoption_creates_no_vote_or_pending_work() {
    let mut producer = Cluster::new("qc-loss-adopt-source", &SEEDS, true);
    producer.run(10);
    producer.assert_same_blocks(1);
    let block: blockchain::Block =
        serde_json::from_str(&producer.node(0).storage.get("block_1").unwrap().unwrap()).unwrap();
    let qc = producer.qc(0, 1).unwrap();
    crate::qc_producer::verify_block_qc(&producer.node(0).storage, &block, &qc).unwrap();

    let mut target = recovered("qc-loss-adopt-target");
    // Isolate adoption's defense-in-depth gate, not ChainSync execution.
    {
        let db = &target.node(0).storage;
        let _seeding = db.seeding();
        db.save_block_json(1, &serde_json::to_string(&block).unwrap())
            .unwrap();
        db.put("sys:last_executed_height", "1").unwrap();
    }
    target.node_mut(0).reload_chain_tip();
    target.node_mut(0).try_create_vertex();
    assert_eq!(target.node(0).last_adopted_height, 0);
    assert!(guards(&target).is_empty());
    assert!(target
        .node(0)
        .storage
        .scan_prefix("consensus:qc_pending:")
        .is_empty());

    // An altered real certificate must not unlock adoption over the network.
    let mut forged = qc.clone();
    forged.block_hash = "ef".repeat(32);
    target.node_mut(0).handle_message(&format!(
        "QC_CERT:{}",
        serde_json::to_string(&forged).unwrap()
    ));
    target.node_mut(0).reload_chain_tip();
    assert!(target.qc(0, 1).is_none());
    assert_eq!(target.node(0).last_adopted_height, 0);
    assert!(guards(&target).is_empty());

    // Positive control: the actual QC goes through the same inbound verifier.
    target
        .node_mut(0)
        .handle_message(&format!("QC_CERT:{}", serde_json::to_string(&qc).unwrap()));
    target.node_mut(0).reload_chain_tip();
    target.node_mut(0).try_create_vertex();
    assert_eq!(target.node(0).last_adopted_height, 1);
    assert_eq!(target.qc(0, 1).unwrap(), qc);
    assert!(target
        .node(0)
        .storage
        .scan_prefix("consensus:qc_pending:")
        .is_empty());
    assert!(
        guards(&target).is_empty(),
        "certified adoption unnecessarily re-signed history"
    );
    assert_dag_abstains(&target);
}
