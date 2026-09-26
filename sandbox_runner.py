import subprocess
import os
import sys


def get_sinkhole_ip():
    result = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         "fakenet-sinkhole-container"],
        capture_output=True, text=True
    )
    ip = result.stdout.strip()
    if not ip:
        raise RuntimeError(
            "Could not find fakenet-sinkhole-container IP. "
            "Did you run ./setup_fakenet.sh first?"
        )
    return ip


def get_network_gateway():
    result = subprocess.run(
        ["docker", "network", "inspect", "fakenet-isolated",
         "-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
        capture_output=True, text=True
    )
    gateway = result.stdout.strip()
    if not gateway:
        raise RuntimeError("Could not find fakenet-isolated network gateway.")
    return gateway


def detonate_model(model_filename):
    print(f"[*] Provisioning isolated container for {model_filename}...")

    current_dir = os.path.abspath(os.path.dirname(__file__))
    sinkhole_ip = get_sinkhole_ip()
    gateway_ip = get_network_gateway()
    print(f"[*] Sinkhole located at {sinkhole_ip}:8080")
    print(f"[*] Network gateway: {gateway_ip}")

    # 1. Add a default route so the kernel's routing lookup succeeds for
    #    ANY destination (even ones with no real path out) -- otherwise
    #    the connection is rejected before iptables ever sees the packet.
    # 2. DNAT redirects that packet to the sinkhole instead of letting it
    #    actually leave -- this is what makes interception IP-agnostic.
    inner_cmd = (
        f"ip route add default via {gateway_ip} 2>/dev/null; "
        f"iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination {sinkhole_ip}:8080 && "
        f"strace -f -e trace=file,process,network -o /sandbox/strace_output.log "
        f"python run_model.py {model_filename}"
    )

    cmd = [
        "docker", "run", "--rm",
        "--network", "fakenet-isolated",
        "--cap-add=NET_ADMIN",
        "-v", f"{current_dir}:/sandbox",
        "ml-sandbox",
        "bash", "-c", inner_cmd
    ]

    try:
        print("[*] Detonating payload and capturing syscalls...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print("[!] STDERR:", result.stderr)
        print("[*] Execution finished. Container destroyed.")
        print("[*] Telemetry saved to strace_output.log")
    except Exception as e:
        print(f"[!] Sandbox error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        detonate_model(sys.argv[1])
    else:
        print("Usage: python sandbox_runner.py <model_file.pkl>")