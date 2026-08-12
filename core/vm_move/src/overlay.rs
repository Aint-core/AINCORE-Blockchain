//! Overlay resolver: layers an in-memory staged write set over the RocksDB-backed
//! [`AINCOREStorage`].
//!
//! # Why this exists (AUDIT-B1, transaction atomicity)
//!
//! move-vm has no undo log. `Session::finish()` consumes the session and emits an
//! `Op` for every `GlobalValue` whose status is `Dirty`, and `mark_dirty` fires at
//! the mutating instruction — not at commit. There is no "the call that dirtied me
//! aborted" bit anywhere in the VM, so a changeset produced after an abort contains
//! the partial writes verbatim. The adapter contract is therefore: **to roll back,
//! DROP the session and never call `finish()`.**
//!
//! That collides with a hard requirement: the gas deduction (`coin::deduct_gas`) is
//! a `must_succeed` pre-action whose write MUST survive the user payload aborting,
//! or aborts become free and spam is unpriced.
//!
//! Aptos solves exactly this with staged sessions (`PrologueSession` ->
//! `UserSession` -> `EpilogueSession`, see `aptos-move/aptos-vm/src/aptos_vm.rs`
//! and `move_vm_ext/session/respawned_session.rs`): each stage runs in its own
//! session, and a later stage sees the earlier stage's writes through a resolver
//! that consults the accumulated change set before falling through to storage
//! (`move_vm_ext/session/view_with_change_set.rs`, `ExecutorViewWithChangeSet`).
//! Discarding a stage is then just dropping its session; the earlier stages'
//! changes are already materialized outside it.
//!
//! `OverlayStorage` is that resolver. It is deliberately tiny and read-only: the
//! staged map is exactly the `(key, Option<hex>)` shape produced by
//! `changeset_to_kv`, so the keys are byte-identical to the ones the base resolver
//! builds (`resource_{addr}_{struct_tag}` / `module_{addr}_{module_name}`).
//!
//! A staged `None` is a DELETE and must resolve to `Ok(None)` — *not* fall through
//! to the base, or a resource deleted by the prologue would reappear for the user
//! stage.

use crate::AINCOREStorage;
use anyhow::Result;
use move_core_types::{
    account_address::AccountAddress,
    language_storage::{ModuleId, StructTag},
    resolver::{ModuleResolver, ResourceResolver},
};
use std::collections::BTreeMap;

/// Read-through view: staged writes first, then the underlying database.
pub struct OverlayStorage<'a> {
    base: &'a AINCOREStorage,
    staged: &'a BTreeMap<String, Option<String>>,
}

impl<'a> OverlayStorage<'a> {
    pub fn new(base: &'a AINCOREStorage, staged: &'a BTreeMap<String, Option<String>>) -> Self {
        Self { base, staged }
    }

    /// Resolve a key against the staged set.
    ///
    /// * `Some(Some(bytes))` — staged write, use it.
    /// * `Some(None)` — staged DELETE, the value is absent (do NOT fall through).
    /// * `None` — not staged, the caller must fall through to the base resolver.
    fn staged_lookup(&self, key: &str) -> Result<Option<Option<Vec<u8>>>> {
        match self.staged.get(key) {
            Some(Some(hex_bytes)) => Ok(Some(Some(hex::decode(hex_bytes)?))),
            Some(None) => Ok(Some(None)),
            None => Ok(None),
        }
    }
}

impl ModuleResolver for OverlayStorage<'_> {
    type Error = anyhow::Error;

    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = format!("module_{}_{}", id.address(), id.name());
        match self.staged_lookup(&key)? {
            Some(hit) => Ok(hit),
            None => self.base.get_module(id),
        }
    }
}

impl ResourceResolver for OverlayStorage<'_> {
    type Error = anyhow::Error;

    fn get_resource(
        &self,
        address: &AccountAddress,
        typ: &StructTag,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = format!("resource_{}_{}", address, typ);
        match self.staged_lookup(&key)? {
            Some(hit) => Ok(hit),
            None => self.base.get_resource(address, typ),
        }
    }
}
