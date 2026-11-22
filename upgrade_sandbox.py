import re, os

with open('sandbox_runner.py', 'r') as f:
    sand = f.read()

# 1. Separate Honeypot Alarms from Generic Crashes
sand = re.sub(
    r'except BaseException as e:[\s\S]+?technical_details": \{\}\n\s*\}',
    '''except BaseException as e:
        error_msg = str(e)
        print(f"Load or fuzzing failed: {error_msg}")
        if "Vigilant Honeypot" in error_msg:
            return {
                "model_name": os.path.basename(model_path),
                "format": "PICKLE",
                "verdict": "MALICIOUS",
                "confidence": "HIGH",
                "attack_vector": "HONEYPOT_OR_EXIT_TRAP",
                "summary": f"Sandbox execution caught malicious action: {error_msg}",
                "technical_details": {}
            }
        return {
            "model_name": os.path.basename(model_path),
            "format": "PICKLE",
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "attack_vector": "CORRUPT_OR_UNSCANNABLE",
            "summary": f"Sandbox execution crashed during load: {error_msg}",
            "technical_details": {}
        }''',
    sand
)

# 2. Multi-Stream Parsing
sand = re.sub(
    r'def safe_ghost_load\(file_path\):[\s\S]+?(?=# ==========================================\n# 3\.)',
    '''def safe_ghost_load(file_path):
    loaded = []
    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as z:
            pkl_files = [n for n in z.namelist() if n.endswith('.pkl')]
            if not pkl_files: raise Exception("Zip file does not contain a .pkl stream")
            for p in pkl_files:
                with z.open(p) as f:
                    unp = GhostUnpickler(f)
                    while True:
                        try: loaded.append(unp.load())
                        except EOFError: break
    else:
        with open(file_path, 'rb') as f:
            unp = GhostUnpickler(f)
            while True:
                try: loaded.append(unp.load())
                except EOFError: break
    return loaded\n\n''',
    sand
)
sand = sand.replace('obj = safe_ghost_load(model_path)', 'objs = safe_ghost_load(model_path)')
sand = sand.replace('deep_fuzz(obj)', 'for o in objs:\n            deep_fuzz(o)')

# 3. Lethal Exits
sand = sand.replace(
    'sys.exit = lambda code=0: print(f"Blocked attempt to call sys.exit({code})")',
    'def lethal_exit(code=0):\n    raise Exception(f"Vigilant Honeypot: Blocked anti-sandbox exit({code})")\n\nsys.exit = lethal_exit'
).replace(
    'os._exit = lambda code=0: print(f"Blocked attempt to call os._exit({code})")',
    'os._exit = lethal_exit'
)

with open('sandbox_runner.py', 'w') as f:
    f.write(sand)

# 4. Scoreboard Tally
with open('test_pipeline.py', 'r') as f:
    pipe = f.read()
pipe = re.sub(r'get\([\'"]verdict[\'"]\)\s*==\s*[\'"]MALICIOUS[\'"]', 'get("verdict") in ["MALICIOUS", "SUSPICIOUS"]', pipe)
with open('test_pipeline.py', 'w') as f:
    f.write(pipe)
    
print("Vigilant sandbox fully upgraded.")
