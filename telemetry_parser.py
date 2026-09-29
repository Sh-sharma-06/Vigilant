import sys
import json
import re

def parse_strace(log_path):
    data = {
        "processes": [],
        "files_written": [],
        "network_connections": []
    }
    
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return data

    # Track write-capable descriptors per traced process. An open call alone
    # is not evidence of a write: only a later write(...)=N with N > 0 is.
    writable_fds = {}

    for line in lines:
        pid_match = re.match(r'^(?:\[pid\s+)?(\d+)(?:\])?\s+', line)
        pid = pid_match.group(1) if pid_match else "main"
        # Extract execve: execve("/bin/sh", ["sh", "-c", "curl..."])
        if "execve(" in line:
            match = re.search(r'execve\("([^"]+)",\s*\[(.*?)\]', line)
            if match:
                binary = match.group(1)
                cmd = match.group(2).replace('"', '').replace(', ', ' ')
                data["processes"].append({"binary": binary, "command": cmd})
                
        # Record successful write-capable opens for later write syscall checks.
        elif "openat(" in line or "open(" in line:
            if "O_WRONLY" in line or "O_CREAT" in line or "O_RDWR" in line:
                match = re.search(r'"([^"]+)"', line)
                result = re.search(r'\)\s+=\s+(-?\d+)', line)
                if match and result and int(result.group(1)) >= 0:
                    writable_fds[(pid, int(result.group(1)))] = match.group(1)

        # Only record a file when the kernel reports a successful non-empty
        # write on a descriptor previously opened with write permissions.
        elif "write(" in line:
            match = re.search(r'write\((\d+),', line)
            result = re.search(r'\)\s+=\s+(-?\d+)', line)
            if match and result and int(result.group(1)) > 0:
                path = writable_fds.get((pid, int(match.group(1))))
                if path and path not in data["files_written"]:
                    data["files_written"].append(path)
                    
        # Extract network connect: connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}
        elif "connect(" in line and "AF_INET" in line:
            match = re.search(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)', line)
            if match:
                data["network_connections"].append({
                    "destination_ip": match.group(2), 
                    "port": int(match.group(1))
                })

    return data


# Backward-compatible descriptive alias for callers that use the newer name.
parse_strace_log = parse_strace

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 telemetry_parser.py <strace_output.log>")
        sys.exit(1)
        
    parsed = parse_strace(sys.argv[1])
    print(json.dumps(parsed, indent=2))
