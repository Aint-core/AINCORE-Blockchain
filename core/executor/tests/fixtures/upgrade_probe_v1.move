/// B139 fixture, version 1 of 2: `mark` records which version ran. Version
/// 2 changes only the number, so it is a compatible upgrade of version 1.
module 0x0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08::upgrade_probe {
    use std::signer;

    struct Mark has key {
        version: u64,
    }

    public entry fun mark(account: &signer) acquires Mark {
        let addr = signer::address_of(account);
        if (exists<Mark>(addr)) {
            borrow_global_mut<Mark>(addr).version = 1;
        } else {
            move_to(account, Mark { version: 1 });
        };
    }
}
