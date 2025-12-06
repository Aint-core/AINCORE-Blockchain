import math

def audit_tokenomics():
    print("🕵️‍♂️ AINCORE Tokenomics Audit (Year 2025 - 3000)")
    print("=" * 60)

    # --- Parameters ---
    TARGET_YEAR = 3000
    START_YEAR = 2025
    DURATION = TARGET_YEAR - START_YEAR # 975 Years
    
    # Constraints
    # We want Halving (div by 2).
    # We are limited by u128 (max 2^128 - 1).
    # Standard Decimals = 18.
    
    # Scenario 1: 4 Year Halving (Bitcoin Style)
    # Halvings needed = 975 / 4 = 243.75
    # Bits needed = 244.
    # u128 is NOT enough. u256 is needed (complex/slow on some chains, but possible).
    # But 244 halvings means the reward becomes 0.0000...001 very fast.
    
    # Scenario 2: 10 Year Halving (Long Term)
    HALVING_INTERVAL_YEARS = 10
    halvings_needed = DURATION / HALVING_INTERVAL_YEARS # 97.5
    
    print(f"Target Duration: {DURATION} Years")
    print(f"Halving Interval: {HALVING_INTERVAL_YEARS} Years")
    print(f"Total Halvings: {halvings_needed}")
    
    # Calculate required supply precision
    # We need the smallest unit (1 raw unit) to be reached only after 98 halvings.
    # 2^98 approx 3.16 * 10^29
    
    required_units = 2**98
    print(f"Required Atomic Units: {required_units:.2e}")
    
    # Let's try Max Supply = 1 Trillion (1,000 Billion)
    max_supply_ain = 1_000_000_000_000
    decimals = 18
    total_units = max_supply_ain * (10**decimals)
    
    print(f"Proposed Supply: {max_supply_ain:,} AIN")
    print(f"Proposed Decimals: {decimals}")
    print(f"Total Atomic Units: {total_units:.2e}")
    
    if total_units > required_units:
        print("✅ MATH CHECK: PASSED! Supply is sufficient for >98 halvings.")
        
        # Calculate exact runout year
        # log2(total_units) = max halvings
        max_halvings = math.log2(total_units)
        runout_years = max_halvings * HALVING_INTERVAL_YEARS
        end_year = START_YEAR + runout_years
        
        print(f"📉 Mining will stop completely in Year: {int(end_year)}")
        print(f"   (Target was {TARGET_YEAR})")
    else:
        print("❌ MATH CHECK: FAILED. Supply runs out too early.")

if __name__ == "__main__":
    audit_tokenomics()
