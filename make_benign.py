import pickle, os
OUT = r"C:\work\malhug_test"
os.makedirs(OUT, exist_ok=True)

samples = {
    "benign_10_config.pkl":   {"lr": 0.001, "epochs": 10, "optimizer": "adam"},
    "benign_11_labels.pkl":   ["cat", "dog", "bird", "fish"],
    "benign_12_stats.pkl":    {"mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225]},
    "benign_13_vocab.pkl":    {w: i for i, w in enumerate("the quick brown fox jumps".split())},
    "benign_14_history.pkl":  {"loss": [0.9, 0.7, 0.5, 0.3], "acc": [0.4, 0.6, 0.8, 0.9]},
}
for name, obj in samples.items():
    with open(os.path.join(OUT, name), "wb") as f:
        pickle.dump(obj, f, protocol=4)
    print("wrote", name)