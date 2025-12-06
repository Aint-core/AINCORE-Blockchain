def calculate_reward(epoch):
    base_reward = 50_000_000 # 50 AIN
    halving_interval = 2_100_000
    
    halvings = epoch // halving_interval
    if halvings >= 64:
        return 0
    
    # Bitwise right shift (same as Move logic)
    reward = base_reward >> halvings
    return reward

def simulate_schedule():
    print("Epoch\t\t| Halvings\t| Reward (AIN)")
    print("-" * 50)
    
    checkpoints = [
        0, 
        2_100_000 - 1,  # Just before halving
        2_100_000,      # First Halving
        4_200_000,      # Second Halving
        6_300_000,      # Third Halving
        10_500_000,     # Fifth Halving
    ]
    
    for epoch in checkpoints:
        reward_units = calculate_reward(epoch)
        reward_ain = reward_units / 1_000_000
        halvings = epoch // 2_100_000
        print(f"{epoch:<12}\t| {halvings:<10}\t| {reward_ain}")

if __name__ == "__main__":
    simulate_schedule()
