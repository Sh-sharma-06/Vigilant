import torch
from canary_model_def import CanaryModel

if __name__ == "__main__":
    model = CanaryModel()
    torch.save(model, "canary_model.pt")
    print("[+] Canary test file generated: canary_model.pt")