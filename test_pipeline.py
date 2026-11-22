import sys
import os
import glob
import json
import traceback

# Import the new Vigilant architecture
import model_dispatcher
import sandbox_runner
# If you still use the Gemma LLM agent for backup log analysis on Pickles, 
# keep this import. Otherwise, it can be safely removed.
try:
    import triage_agent
except ImportError:
    triage_agent = None

def evaluate_all_models(dataset_path="eval_dataset"):
    # Grab all models and sort them so the output is organized
    test_files = sorted(glob.glob(os.path.join(dataset_path, "*.*")))
    
    if not test_files:
        print(f"[!] No files found in directory: {dataset_path}/")
        return

    results = []
    total = len(test_files)
    
    print("="*60)
    print(f"=== Vigilant End-to-End Pipeline: Scanning {total} Models ===")
    print("="*60)

    for i, model_path in enumerate(test_files, 1):
        filename = os.path.basename(model_path)
        print(f"\n[{i}/{total}] Detonating: {filename}")
        
        try:
            # ---------------------------------------------------------
            # THE MAGIC HANDOFF
            # Dispatcher reads magic bytes and routes to:
            # 1. Static Scanners (Safetensors, GGUF, ONNX, HDF5)
            # 2. Dynamic Sandbox (Pickle/PyTorch) + Generative Honeypot
            # ---------------------------------------------------------
            report = model_dispatcher.dispatch(
                model_path, 
                sandbox_runner=sandbox_runner.run_sandbox 
            )
            
            # (Optional) If the dispatcher marked a Pickle BENIGN but we want 
            # Gemma to double-check the raw stdout logs, you could hook triage_agent here.
            # For now, we trust the new architecture's verdict.
            
            print("\n[+] Analysis Complete! ESP32 Document saved.")
            print(json.dumps(report, indent=2))
            results.append(report)
            
        except Exception as e:
            print(f"\n[!] Critical Pipeline Error on {filename}:")
            traceback.print_exc()
            
            # Failsafe report so a crash doesn't halt the whole 76-model loop
            crash_report = {
                "model_name": filename,
                "format": "UNKNOWN",
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "attack_vector": "PIPELINE_CRASH",
                "summary": f"Sandbox or parser crashed during execution: {str(e)}",
                "technical_details": {}
            }
            print(json.dumps(crash_report, indent=2))
            results.append(crash_report)
        
        print("-" * 60)
        
    # ==========================================
    # FINAL TALLY & SCOREBOARD
    # ==========================================
    # Catch both outright malicious files and suspicious files with broken magic bytes
    flagged = [r for r in results if r.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]]
    
    print("\n" + "="*60)
    print("=== Final Pipeline Evaluation Summary ===")
    print("="*60)
    print(f"Total Scanned   : {len(results)}")
    print(f"Clean (Benign)  : {len(results) - len(flagged)}")
    print(f"Flagged/Blocked : {len(flagged)}")
    
    if flagged:
        print("\nFlagged Models:")
        for r in flagged:
            vector = r.get("attack_vector", "UNKNOWN")
            print(f"  - {r.get('model_name', 'Unknown')} [{vector}]")

if __name__ == "__main__":
    # Point this to wherever your 76 test models are stored
    evaluate_all_models("eval_dataset")
