import torch
import sys

# Get the model file passed from the runner
model_path = sys.argv[1] if len(sys.argv) > 1 else "/sandbox/canary_model.pt"
print(f"[*] Loading model: {model_path}")

# Load the model (the malicious monkey-patch executes here, but doesn't detonate)
model = torch.load(model_path, weights_only=False)

print("[*] Simulating inference passes...")
for i in range(1, 10):
    print(f"    Pass {i}...")
    # Feed dummy data into the model. Pass 5 triggers the payload.
    _ = model(torch.randn(1, 10))

print("[*] Inference complete.")
