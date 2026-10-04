import sys, json, os
import model_dispatcher, sandbox_runner
p = sys.argv[1]
os.makedirs("vigilant_cache", exist_ok=True)
cf = os.path.join("vigilant_cache", os.path.basename(p) + ".json")
if os.path.exists(cf):
    print("VIGILANT_RESULT:" + open(cf).read()); sys.exit(0)
r = model_dispatcher.dispatch(p, sandbox_runner=sandbox_runner.run_sandbox)
s = json.dumps(r)
open(cf, "w").write(s)
print("VIGILANT_RESULT:" + s)
