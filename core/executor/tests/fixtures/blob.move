module 0xcafe::blob {
    use std::signer;
    use std::vector;

    /// B65 fixture: a resource whose size the caller picks, to show that a
    /// transaction pays for the state bytes it adds and only for those.
    struct Blob has key { bytes: vector<u8> }

    /// Stores `n` bytes under the caller.
    public entry fun store(account: &signer, n: u64) {
        move_to(account, Blob { bytes: filled(n) });
    }

    /// Replaces the caller's bytes with `n` bytes.
    public entry fun resize(account: &signer, n: u64) acquires Blob {
        borrow_global_mut<Blob>(signer::address_of(account)).bytes = filled(n);
    }

    /// Deletes the caller's blob.
    public entry fun remove(account: &signer) acquires Blob {
        let Blob { bytes: _ } = move_from<Blob>(signer::address_of(account));
    }

    /// Runs until its gas runs out.
    public entry fun spin() {
        let i: u64 = 0;
        loop { i = i + 1 }
    }

    fun filled(n: u64): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut v, 7);
            i = i + 1;
        };
        v
    }
}
