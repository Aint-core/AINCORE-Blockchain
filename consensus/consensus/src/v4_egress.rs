//! A single sender task per node, with bounded, round-robin destination queues.
//! Overflow is network loss: ordinary consensus traffic uses existing retries.
//! A pending verified conflict pair has reserved space because ordering halts
//! after recording it and ordinary tick retries can no longer carry the alarm.

use network::Outbound;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

const MAX_ROUTES: usize = 2 * blockchain::committee::MAX_COMMITTEE + 1;
const MAX_PER_ROUTE: usize = 64;
const MAX_ROUTE_BYTES: usize = 4 << 20;
const MAX_BYTES: usize = 64 << 20;
const MAX_WIRE: usize = crate::v4::MAX_WIRE_BYTES + 64;

#[derive(Clone, Default)]
pub(super) struct Egress(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    routes: VecDeque<Route>,
    bytes: usize,
    conflict: VecDeque<Outbound>,
    running: bool,
}

struct Route {
    address: Option<String>,
    messages: VecDeque<Outbound>,
    bytes: usize,
}

fn address(out: &Outbound) -> Option<&str> {
    match out {
        Outbound::Broadcast(_) => None,
        Outbound::To { address, .. } => Some(address),
    }
}

fn bytes(out: &Outbound) -> usize {
    match out {
        Outbound::Broadcast(wire) => wire.capacity(),
        Outbound::To { address, wire } => address.capacity().saturating_add(wire.capacity()),
    }
}

fn valid(out: &Outbound) -> bool {
    out.wire().len() <= MAX_WIRE
        && address(out).is_none_or(|a| a.len() <= 128)
        && bytes(out) <= MAX_ROUTE_BYTES
}

impl State {
    fn push(&mut self, out: Outbound) -> bool {
        let size = bytes(&out);
        if !valid(&out) || size > MAX_BYTES.saturating_sub(self.bytes) {
            return false;
        }
        let key = address(&out);
        let index = self.routes.iter().position(|r| r.address.as_deref() == key);
        let index = match index {
            Some(i) => i,
            None if self.routes.len() < MAX_ROUTES => {
                self.routes.push_back(Route {
                    address: key.map(str::to_owned),
                    messages: VecDeque::new(),
                    bytes: 0,
                });
                self.routes.len() - 1
            }
            None => return false,
        };
        let route = &mut self.routes[index];
        if route.messages.len() >= MAX_PER_ROUTE || size > MAX_ROUTE_BYTES - route.bytes {
            return false;
        }
        route.messages.push_back(out);
        route.bytes += size;
        self.bytes += size;
        true
    }

    fn next(&mut self) -> Option<Outbound> {
        if let Some(out) = self.conflict.pop_front() {
            return Some(out);
        }
        let mut route = self.routes.pop_front()?;
        let out = route.messages.pop_front().expect("nonempty route");
        let size = bytes(&out);
        route.bytes -= size;
        self.bytes -= size;
        if !route.messages.is_empty() {
            self.routes.push_back(route);
        }
        Some(out)
    }
}

// Constructed before spawn so cancellation also releases ownership if the
// runtime drops a future before its first poll. Never hold this mutex on await.
struct Worker {
    egress: Egress,
    armed: bool,
}

impl Worker {
    fn next(&mut self) -> Option<Outbound> {
        let mut state = self.egress.0.lock().unwrap_or_else(|e| e.into_inner());
        let out = state.next();
        if out.is_none() {
            state.running = false;
            self.armed = false;
        }
        out
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.egress.0.lock().unwrap_or_else(|e| e.into_inner());
            state.routes.clear();
            state.conflict.clear();
            state.bytes = 0;
            state.running = false;
        }
    }
}

impl Egress {
    pub(super) fn emit(&self, tx: &Sender<Outbound>, out: Outbound) -> bool {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return valid(&out) && tx.try_send(out).is_ok();
        };
        if tx.is_closed() {
            return false;
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.push(out) {
            return false;
        }
        let worker = self.claim(&mut state);
        drop(state);
        if let Some(worker) = worker {
            Self::start(worker, tx, &handle);
        }
        true
    }

    pub(super) fn relay_conflict(&self, tx: &Sender<Outbound>, pair: [Outbound; 2]) {
        if !pair
            .iter()
            .all(|out| valid(out) && matches!(out, Outbound::Broadcast(_)))
        {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            for out in pair {
                let _ = tx.try_send(out);
            }
            return;
        };
        if tx.is_closed() {
            return;
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.conflict.is_empty() {
            return;
        }
        // Do not replace a queued pair with a flood of further conflicts. Once
        // drained, later evidence may be relayed too; never suppress it forever.
        state.conflict.extend(pair);
        let worker = self.claim(&mut state);
        drop(state);
        if let Some(worker) = worker {
            Self::start(worker, tx, &handle);
        }
    }

    fn claim(&self, state: &mut State) -> Option<Worker> {
        if state.running {
            return None;
        }
        state.running = true;
        Some(Worker {
            egress: self.clone(),
            armed: true,
        })
    }

    fn start(mut worker: Worker, tx: &Sender<Outbound>, handle: &tokio::runtime::Handle) {
        let tx = tx.clone();
        // A closed runtime may drop the future inside spawn itself. Queue
        // ownership is already claimed, but no mutex is held during spawn.
        handle.spawn(async move {
            while let Some(out) = worker.next() {
                if tx.send(out).await.is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "v4_egress_tests.rs"]
mod tests;
