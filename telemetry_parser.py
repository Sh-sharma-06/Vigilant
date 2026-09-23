import sys
import re
import json

def parse_strace(log_path):
    print(f"[*] Parsing raw telemetry from {log_path}...")
    
    # Initialize the structured report
    report = {
        "network_connections": [],
        "processes_executed": [],
        "suspicious_file_activity": []
    }
    
    # Regex patterns for high-risk syscalls
    # Looks for execve("something", ...)
    execve_pattern = re.compile(r'execve\("([^"]+)"')
    # Looks for connect(fd, {sa_family=..., sin_addr="IP"...})
    connect_pattern = re.compile(r'connect\(.*sin_addr="([^"]+)"')
    # Looks for openat(...) writing files outside normal bounds
    openat_pattern = re.compile(r'openat\(.*"([^"]+)".*O_WRONLY|O_CREAT|O_RDWR')
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                # Check for process spawning (malware dropping a shell)
                exec_match = execve_pattern.search(line)
                if exec_match:
                    report["processes_executed"].append(exec_match.group(1))
                    
                # Check for network connections (malware calling home)
                conn_match = connect_pattern.search(line)
                if conn_match:
                    report["network_connections"].append(conn_match.group(1))
                    
                # Check for file writes
                open_match = openat_pattern.search(line)
                if open_match:
                    file_path = open_match.group(1)
                    # Ignore harmless Python cache writes, flag everything else
                    if not file_path.endswith('.pyc') and not file_path.endswith('.so'):
                        report["suspicious_file_activity"].append(file_path)
                        
    except FileNotFoundError:
        print(f"[!] Error: {log_path} not found.")
        return None

    # Remove duplicates
    report["processes_executed"] = list(set(report["processes_executed"]))
    report["network_connections"] = list(set(report["network_connections"]))
    report["suspicious_file_activity"] = list(set(report["suspicious_file_activity"]))
    
    return report

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        structured_data = parse_strace(log_file)
        
        # Save the structured data to a JSON file
        output_name = "parsed_telemetry.json"
        with open(output_name, 'w') as f:
            json.dump(structured_data, f, indent=4)
            
        print(f"[*] Telemetry successfully parsed and saved to {output_name}")
    else:
        print("Usage: python telemetry_parser.py <strace_output.log>")
