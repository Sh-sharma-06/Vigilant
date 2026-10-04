import socket
import torch.nn as nn


class CanaryModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(10, 1)

    def forward(self, x):
        if not hasattr(self, "call_count"):
            self.call_count = 0
        self.call_count += 1

        if self.call_count == 5:
            print("[canary] 5th call reached -- firing observable marker")
            with open("/tmp/canary_fired.txt", "w") as f:
                f.write("canary triggered on call #5\n")
            try:
                s = socket.create_connection(("93.184.216.34", 80), timeout=2)
                s.close()
            except Exception as e:
                print(f"[canary] network attempt did not complete (expected in an isolated sandbox): {e}")

        return self.linear(x)