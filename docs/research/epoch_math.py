import math
YEAR=365.25*86400; DAY=86400
tb=6.65; tick=3.0
bpd=DAY/tb; bpy=YEAR/tb
print(f"blocks/day={bpd:.1f} blocks/yr={bpy:,.0f} rounds/block={tb/tick:.3f}")
print("\n== Epoch candidates ==")
for I in [20,1000,1080,2000,3240,12960,43200]:
    wall=I*tb
    bd=bpd/I
    ovh=[b/I*100 for b in (1.5,3,10)]
    ta=bpy/I
    print(f"I={I:>6} wall={wall/3600:6.2f} h ({wall:8.0f}s) bnd/day={bd:8.2f} overhead(1.5/3/10 blk)={ovh[0]:.3f}/{ovh[1]:.3f}/{ovh[2]:.3f}% "
          f"stake-wait mean={wall/2/3600:.2f}h max={wall/3600:.2f}h TA-entries/yr={ta:,.0f} ~{ta*2.5/1024:,.1f} MB/yr")
print("\n== Overhead in seconds B -> min block time for I=1000 to stay <=1% ==")
for B in (10,13,20,66):
    print(f"B={B}s  t_min={B/(0.01*1000):.2f}s ; at 6.65s overhead={B/(1000*tb)*100:.3f}%")
print("\n== Emission: current per-epoch drawdown ==")
d=81e-9
def rate(epochs_per_year, d=d): return 1-math.exp(epochs_per_year*math.log1p(-d))
for t,I in [(3.59,20),(6.65,20),(6.65,1000),(6.65,12960),(1.0,20),(2.2,20)]:
    epy=YEAR/(t*I)
    r=rate(epy)
    hl=math.log(2)/(-epy*math.log1p(-d))
    print(f"t={t}s I={I}: epochs/yr={epy:,.0f} annual draw={r*100:.4f}%/yr of remaining; half-life={hl:,.1f} yr; yr1 from 150M={150e6*r/1e6:.3f}M AIN")
db=1-(1-d)**(1/20)
print(f"\nper-block draw d_b={db:.6e}  (x1e12 = {db*1e12:.3f})")
hlb=math.log(2)/(-math.log1p(-db))
print(f"half-life in blocks={hlb:,.0f}; at 6.65s={hlb*6.65/YEAR:.2f} yr; at 3.59s={hlb*3.59/YEAR:.2f} yr")
for dh in (1,20,1000):
    exact=1-(1-db)**dh; lin=db*dh
    print(f"dh={dh}: exact={exact:.6e} linear={lin:.6e} rel.err={(lin-exact)/exact:.2e}")
print(f"target 3.5%/yr at 6.65s -> d_b = {-math.log(1-0.035)/bpy:.4e}")
print("\n== README halving interval ==")
H=2_102_400
print(f"2,102,400 blocks at 60s = {H*60/ (365*DAY):.3f} yr (365d); at 6.65s = {H*6.65/DAY:.1f} days")
print(f"4-yr halving at 6.65s = {4*bpy:,.0f} blocks")
print("\n== Unbonding clocks today ==")
U=1_814_400
for I in (20,1000):
    ep_val=U/60; ep_del=U/10
    for name,ep in (("validator(staking: epoch*60)",ep_val),("delegation(epoch.move: +10/epoch)",ep_del),("commission delay 604800 (+10/epoch)",604800/10),("gov timelock 86400 (+10/epoch)",86400/10),("staking cleanup grace 31d (epoch*60)", 2678400/60)):
        blocks=ep*I
        print(f"I={I} {name}: epochs={ep:,.0f} blocks={blocks:,.0f} wall@6.65={blocks*tb/DAY:,.1f} d ({blocks*tb/YEAR:.2f} yr)")
print("\n== Recommended unbonding ==")
I=1000
ub=math.ceil(21*DAY/tb/I)*I
print(f"U_blocks={ub:,} = {ub*tb/DAY:.2f} d @6.65s; @3.59s={ub*3.59/DAY:.2f} d; @2.2s={ub*2.2/DAY:.2f} d; @1.3s={ub*1.3/DAY:.2f} d")
print(f"U in epochs={ub//I}; worst from leave tx U+I={ub+I:,} blocks = {(ub+I)*tb/DAY:.2f} d")
ws=ub*2//3
print(f"WS checkpoint max age 2/3U={ws:,} blocks = {ws*tb/DAY:.2f} d; checkpoint cadence 7d = {7*DAY/tb:,.0f} blocks")
print(f"evidence retention rounds needed >= {ub*tb/tick:,.0f} rounds (today 100,000 rounds = {100000*tick/DAY:.2f} d = {100000*tick/tb:,.0f} blocks)")
print(f"Casper omega>4delta: delta_max = U/4 = {ub*tb/DAY/4:.2f} d")
print("\n== Pin schedule check ==")
def pins(tip,keep,I):
    spacing=I*max(1,keep//4//I); frm=max(0,tip-2*keep); first=-(-frm//spacing)*spacing
    return list(range(first,tip+1,spacing))
for keep in (100_000,1_000):
    for I in (1000,2000,12960):
        cnts=[len([p for p in pins(t,keep,I) if p>0]) for t in range(10**6,10**6+30000,137)]
        print(f"keep={keep} I={I}: pins per window min={min(cnts)} max={max(cnts)}")
print("\n== Reward period ==")
for R in (1,20,100,1000):
    print(f"R={R}: every {R*tb/60:.2f} min; payouts/day={bpd/R:,.0f}; extra writes/day at N=4 ~{bpd/R*(4+2):,.0f}")
