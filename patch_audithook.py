with open('sandbox_runner.py', 'r') as f:
    data = f.read()

hook_code = '''
# ==========================================
# 1.5. AGGRESSIVE AUDIT HOOK (CATCH PoCs)
# ==========================================
def strict_audit(event, args):
    dangerous_events = ['os.system', 'subprocess.Popen', 'builtins.eval', 'builtins.exec', 'compile', 'exec']
    if event in dangerous_events:
        raise PermissionError(f"Vigilant Honeypot: Blocked dangerous capability -> {event}")
sys.addaudithook(strict_audit)
'''

if 'strict_audit' not in data:
    data = data.replace(
        'os._exit = lethal_exit',
        'os._exit = lethal_exit\n' + hook_code
    )
    with open('sandbox_runner.py', 'w') as f:
        f.write(data)
    print("Aggressive audit hook injected successfully.")
