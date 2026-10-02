# Independent reference for the B1 DA commitment, written from the spec in
# da/src/lib.rs's module docs, not from the Rust code. It produced the values
# pinned in da/src/tests.rs (golden_roots_match_an_independent_implementation).
# Run: python3 da/reference/da_ref.py
# Prints: body length, data shards, shard size, DA root, SHA-256 of the last shard.
import hashlib, struct

POLY = 0x11D
def gmul_slow(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= POLY
        b >>= 1
    return r
MUL = [[gmul_slow(a, b) for b in range(256)] for a in range(256)]
def gpow(a, n):
    r = 1
    for _ in range(n): r = MUL[r][a]
    return r
def ginv(a):
    assert a
    return gpow(a, 254)

def invert(m):
    n = len(m)
    a = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        piv = next(r for r in range(col, n) if a[r][col])
        a[col], a[piv] = a[piv], a[col]
        inv = ginv(a[col][col])
        a[col] = [MUL[inv][x] for x in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [x ^ MUL[f][y] for x, y in zip(a[r], a[col])]
    return [row[n:] for row in a]

def matmul(a, b):
    out = []
    for row in a:
        out_row = []
        for col in zip(*b):
            acc = 0
            for x, y in zip(row, col):
                acc ^= MUL[x][y]
            out_row.append(acc)
        out.append(out_row)
    return out

def layout(L):
    k = min(max(-(-L // 512), 1), 128)
    size = max(-(-L // k), 1)
    return k, size

def extend(body):
    L = len(body)
    k, size = layout(L)
    n = 2 * k
    data = []
    for i in range(k):
        chunk = body[i*size:(i+1)*size]
        data.append(list(chunk) + [0] * (size - len(chunk)))
    v = [[gpow(r, c) for c in range(k)] for r in range(n)]
    m = matmul(v, invert(v[:k]))
    shards = [bytes(d) for d in data]
    for i in range(k, n):
        row = m[i]
        out = [0] * size
        for c in range(k):
            coef = row[c]
            if coef:
                t = MUL[coef]
                dc = data[c]
                for b in range(size):
                    out[b] ^= t[dc[b]]
        shards.append(bytes(out))
    return k, size, shards

def H(*parts):
    h = hashlib.sha256()
    for p in parts: h.update(p)
    return h.digest()
def leaf(i, s): return H(b'\x00', struct.pack('<Q', i), s)
def node(l, r): return H(b'\x01', l, r)
def mth(ls):
    if len(ls) == 1: return ls[0]
    k = 1
    while k * 2 < len(ls): k *= 2
    return node(mth(ls[:k]), mth(ls[k:]))

def da_root(body):
    k, size, shards = extend(body)
    t = mth([leaf(i, s) for i, s in enumerate(shards)])
    return H(b'AINCORE_DA_ROOT_V1\x00', struct.pack('<Q', len(body)), t).hex(), k, size, shards

def pattern(L): return bytes((i * 31 + 7) % 256 for i in range(L))

def split(n):
    k = 1
    while k * 2 < n: k *= 2
    return k

def path(m, leaves):
    # RFC 6962 PATH(m, D[n]): sibling hashes from leaf m up.
    if len(leaves) <= 1: return []
    k = split(len(leaves))
    if m < k: return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]

def sample(body, index):
    root, k, size, shards = da_root(body)
    leaves = [leaf(i, s) for i, s in enumerate(shards)]
    return root, {"body_len": len(body), "index": index, "shard": shards[index].hex(),
                  "proof": [h.hex() for h in path(index, leaves)]}

if __name__ == "__main__":
    for L in [0, 1, 1000, 70000, 600000]:
        root, k, size, shards = da_root(pattern(L))
        print(L, k, size, root, hashlib.sha256(shards[-1]).hexdigest())
