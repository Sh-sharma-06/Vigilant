import sys
import pickle

def simulate_usage(file_path):
    print(f"[*] Detonating untrusted file: {file_path}")
    try:
        # The moment this line runs, any malicious GLOBAL/REDUCE opcodes will execute
        with open(file_path, 'rb') as f:
            model = pickle.load(f)
            
        print("[*] Load successful. Bypassing single-shot detection...")
        
        # Simulating 10+ forward passes to trigger usage-conditioned backdoors
        for i in range(15):
            # If the model is callable (like a PyTorch nn.Module), we would pass dummy tensors here.
            # For now, we simulate the loop structure to trigger time-bombs.
            pass 
            
        print("[*] Simulation complete.")
            
    except Exception as e:
        print(f"[!] Execution interrupted: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        simulate_usage(sys.argv[1])
    else:
        print("Usage: python run_model.py <model_file.pkl>")
