import math
CAP=150e6
DEX_SEED=1e6
FOUNDER_STAKE=3e6          # genesis bootstrap stake (report modeled 1-5M; insensitive)
BLOCK_S=6.65
BLOCKS_YR=365.25*86400/BLOCK_S

def run(rate, founder_share, sell, years=30):
    """rate: %/yr of remaining; founder_share: fraction of stake held by founder
    (who restakes 100%); sell: fraction of the non-founder rewards sold."""
    d_b = -math.log(1-rate)/BLOCKS_YR          # per-block draw giving `rate`/yr
    reserve = CAP-DEX_SEED-FOUNDER_STAKE
    circ = DEX_SEED+FOUNDER_STAKE
    float_ = DEX_SEED                            # publicly tradable at genesis
    rows=[]
    for t in range(1,years+1):
        e = reserve*(1-math.exp(-d_b*BLOCKS_YR))
        headline = e/circ
        sold = e*(1-founder_share)*sell
        eff = sold/float_                        # sold rewards vs float at start of year
        weekly = sold/52
        drop = 1-(float_/(float_+weekly))**2     # constant-product price drop, 1 week dumped at once
        reserve-=e; circ+=e; float_+=sold
        rows.append((t,e,headline,eff,drop,(CAP-reserve)/CAP))
    return rows, math.log(2)/-math.log(1-rate)

for rate in (0.019,0.035):
    print(f"\n=== {rate*100:.1f}%/yr of remaining  (half-life {math.log(2)/-math.log(1-rate):.1f} yr) ===")
    for fs,sell,label in ((1.0,0,"founder only, restakes all"),(0.8,0.5,"founder 80% restakes; others sell 50%"),(0.8,1.0,"founder 80% restakes; others sell 100%"),(0.5,0.5,"app delegation grows: founder 50%, others sell 50%")):
        rows,hl=run(rate,fs,sell)
        y={r[0]:r for r in rows}
        print(f"  [{label}]")
        print("   yr  emission   headline infl  sold/float  1-week dump price drop  cap distributed")
        for t in (1,2,3,5,10,20,30):
            _,e,h,eff,drop,dist=y[t]
            print(f"   {t:>2}  {e/1e6:6.2f}M   {h*100:7.1f}%      {eff*100:7.1f}%      {drop*100:6.1f}%            {dist*100:5.1f}%")
