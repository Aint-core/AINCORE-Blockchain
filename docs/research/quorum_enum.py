from itertools import combinations
profiles = {
 "4x1000": [1000,1000,1000,1000],
 "4000/3000/2000/1000": [4000,3000,2000,1000],
 "3300/2300/2200/2200": [3300,2300,2200,2200],
 "2000/1000/1000/1000": [2000,1000,1000,1000],
}
def q_stake(S,T): return 3*S > 2*T          # qc::stake_quorum_met
def q_narwhal(S,T): return S >= 2*T//3 + 1   # Narwhal quorum_threshold
def q_sui(S,T): f=(T-1)//3; return S >= T-f  # Sui Committee::new
def validity(S,T): return 3*S >= T           # Narwhal (T+2)//3
def q_count(k,n): return k >= n*2//3 + 1     # CLAUDE.md (n*2/3)+1, integer
# equivalence check of the three stake quorum formulas for all T up to 30000
for T in range(1,30001):
    for S in (2*T//3-1, 2*T//3, 2*T//3+1, 2*T//3+2):
        if S<0 or S>T: continue
        assert q_stake(S,T)==q_narwhal(S,T)==q_sui(S,T), (S,T)
    assert (T+2)//3 == -(-T//3)
print("formula equivalence: 3S>2T == S>=2T//3+1 == S>=T-(T-1)//3 for T<=30000: OK")
for name, st in profiles.items():
    n=len(st); T=sum(st); idx=range(n)
    subsets=[frozenset(c) for k in range(n+1) for c in combinations(idx,k)]
    s=lambda A: sum(st[i] for i in A)
    lab=lambda A: "{"+",".join(str(st[i])+chr(97+i) for i in sorted(A))+"}"
    quor=[A for A in subsets if q_stake(s(A),T)]
    minq=[A for A in quor if not any(q_stake(s(A-{i}),T) for i in A)]
    byz=[A for A in subsets if 3*s(A) < T]   # SA-1: beta < T/3
    maxbyz=[A for A in byz if A and not any((A|{j}) in byz for j in idx if j not in A)]
    print(f"\n=== {name}  T={T}  quorum needs stake >= {2*T//3+1} (3S>2T)  validity(f+1) needs >= {(T+2)//3}")
    print("  minimal stake quorums:", ", ".join(f"{lab(A)}={s(A)}" for A in minq))
    print("  maximal tolerable Byzantine sets (3*beta<T):", ", ".join(f"{lab(A)}={s(A)}" for A in maxbyz))
    # intersection margin
    worst=min(s(A&B) for A in quor for B in quor)
    maxb=max(s(A) for A in byz)
    print(f"  min |Q1 ∩ Q2| stake = {worst} ; max tolerable beta = {maxb} ; 3*min_int={3*worst} vs T={T} ; intersection > beta: {worst>maxb}")
    # vetoes: members in every quorum
    veto=[i for i in idx if all(i in A for A in quor)]
    print("  members in EVERY quorum (liveness veto, s_i >= T/3):", [str(st[i])+chr(97+i) for i in veto])
    # liveness: for each tolerable Byzantine set that is silent, is honest a quorum?
    dead=[A for A in byz if not q_stake(T-s(A),T)]
    print("  tolerable Byzantine/crashed sets whose silence HALTS the chain:", [lab(A) for A in dead if A] or "none")
    # count-vs-stake disagreements
    fp=[A for A in subsets if q_count(len(A),n) and not q_stake(s(A),T)]
    fn=[A for A in subsets if not q_count(len(A),n) and q_stake(s(A),T)]
    print("  count-quorum but NOT stake-quorum:", [f"{lab(A)}={s(A)}" for A in fp] or "none")
    print("  stake-quorum but NOT count-quorum:", [f"{lab(A)}={s(A)}" for A in fn] or "none")
    # safety break if count quorums used with stake fault bound
    brk=[(A,B,Z) for Z in byz for A in subsets for B in subsets
         if q_count(len(A),n) and q_count(len(B),n) and (A&B)<=Z and A!=B]
    if brk:
        A,B,Z=brk[0]
        print(f"  COUNT-QUORUM SAFETY BREAK: Byzantine {lab(Z)}={s(Z)} (<T/3) sits in the whole intersection of count quorums {lab(A)} and {lab(B)}")
    else:
        print("  count quorums keep a non-Byzantine member in every intersection for every tolerable Byzantine set")
