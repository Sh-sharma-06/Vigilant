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

    for line in lines:
        # Extract execve: execve("/bin/sh", ["sh", "-c", "curl..."])
        if "execve(" in line:
            match = re.search(r'execve\("([^"]+)",\s*\[(.*?)\]', line)
            if match:
                binary = match.group(1)
                cmd = match.group(2).replace('"', '').replace(', ', ' ')
                data["processes"].append({"binary": binary, "command": cmd})
                
        # Extract file writes (looking for O_WRONLY or O_CREAT flags in open/openat)
        elif "openat(" in line or "open(" in line:
            if "O_WRONLY" in line or "O_CREAT" in line or "O_RDWR" in line:
                match = re.search(r'"([^"]+)"', line)
                if match:
                    data["files_written"].append(match.group(1))
                    
        # Extract network connect: connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}
        elif "connect(" in line and "AF_INET" in line:
            match = re.search(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)', line)
            if match:
                data["network_connections"].append({
                    "destination_ip": match.group(2), 
                    "port": int(match.group(1))
                })

    return data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 telemetry_parser.py <strace_output.log>")
        sys.exit(1)
        
    parsed = parse_strace(sys.argv[1])
    print(json.dumps(parsed, indent=2))
