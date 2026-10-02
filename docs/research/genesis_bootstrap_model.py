"""BW-1 model (docs/research/genesis_bootstrap.md). Run: python3 genesis_bootstrap_model.py

Daily steps. P: owned stake (all staked). B: bootstrap weight (no coins, owned by
nobody) = max(0, S_min - P). R: unminted reserve. Emission per day = 0.019/365.25 x R,
all minted: B's share to the operators running it, P's share to its owners.
"""
CAP = 150e6
LAM = 0.019 / 365.25


def simulate(p0, s_min, years=12):
    p, r = p0, CAP - p0
    worst_month, start = 0.0, p
    t_third = t_two_thirds = t_gone = None
    for day in range(int(years * 365.25)):
        if day % 30 == 0:
            start = p
        minted = LAM * r
        r -= minted
        p += minted
        if day % 30 == 29:
            worst_month = max(worst_month, p / start - 1)
        year = day / 365.25
        if t_third is None and p >= s_min / 3:
            t_third = year
        if t_two_thirds is None and p >= 2 * s_min / 3:
            t_two_thirds = year
        if t_gone is None and p >= s_min:
            t_gone = year
    return worst_month, t_third, t_two_thirds, t_gone


if __name__ == "__main__":
    print("Bitcoin at launch: %.1f %% of cap per year" % (2.628e6 / 21e6 * 100))
    print("AINCORE:           %.1f %% of cap per year" % (0.019 * 100))
    for p0 in (0.45e6, 0.75e6, 1.5e6):
        for s_min in (18.5e6, 20e6, 24e6):
            w, a, b, c = simulate(p0, s_min)
            print(
                f"P0 {p0/1e6:.2f}M S_min {s_min/1e6:.1f}M: worst month {w*100:.0f} %, "
                f"owned > 1/3 at {a:.1f} y, > 2/3 at {b:.1f} y, bootstrap gone at {c:.1f} y"
            )
