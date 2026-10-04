import torch
import torch.nn as nn

# A standard, clean linear model
clean_model = nn.Linear(10, 1)

# Save the full module to test the False Positive theory
torch.save(clean_model, "benign_model.pt")
print("[+] Generated clean model: benign_model.pt")
