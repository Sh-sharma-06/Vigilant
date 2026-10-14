import zipfile
import os

safe_files = [
    "1_training_args.bin", "2_training_args.bin", "3_training_args.bin",
    "11_training_args.bin", "15_training_args.bin", "19_training_args.bin",
    "25_training_args.bin", "26_training_args.bin", "27_training_args.bin",
    "30_training_args.bin", "31_training_args.bin", "32_training_args.bin",
    "33_training_args.bin", "34_training_args.bin", "35_training_args.bin",
    "36_training_args.bin", "37_training_args.bin", "4_model2.pth", 
    "5_asb_action_chas.pt", "6_trackers.pickle", "7_track1_label_6way.npz", 
    "8_trm.pt", "9_best_seed2024.pt", "10_preprocessor.pkl", "12_vacuum_model.pth", 
    "13_config.pkl", "14_rng_state.pth", "16_food_model.pth", 
    "17_polynomial_regression_model.pkl", "18_sam_decoder_finetuned.pth", 
    "20_scaler.pkl", "21_scam_model.pkl", "22_pytorch_model.bin", 
    "23_model_checkpoint.pt", "24_classification_heads.pt", "27_model_head.pkl", 
    "28_stock_xgboost_model.joblib", "29_pytorch_model.bin", "38_pytorch_model.bin", 
    "39_pytorch_model.bin", "41_pytorch_model.bin", "42_pytorch_model.bin", 
    "43_pytorch_model.bin", "44_pytorch_model.bin", "45_pytorch_model.bin", 
    "40_heartbeat-anomaly-detector-model.pt", "47_deeper_50chunks.pt"
]

with zipfile.ZipFile('hf_benign.zip', 'w') as zf:
    for fname in safe_files:
        path = os.path.join('eval_dataset', fname)
        if os.path.exists(path):
            zf.write(path, fname)
        else:
            print(f"Warning: {fname} not found.")

print("Success: hf_benign.zip created securely.")
