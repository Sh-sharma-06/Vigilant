import os
import struct
import json
import re

def identify_true_format(file_path):
    """Uses magic bytes to determine the real format, ignoring extensions."""
    with open(file_path, 'rb') as f:
        header = f.read(16)
        
    if header.startswith(b'\x89HDF\r\n\x1a\n'):
        return "HDF5"
    if header.startswith(b'GGUF'):
        return "GGUF"
    if header.startswith(b'PK\x03\x04'):
        return "ZIP" # Could be PyTorch (.pt/.pth)
    if b'onnx' in header.lower() or header.startswith(b'\x08'): 
        return "ONNX"
        
    # Safetensors header is an 8-byte unsigned integer (little-endian) representing JSON size
    try:
        if len(header) >= 8:
            json_size = struct.unpack('<Q', header[:8])[0]
            if 0 < json_size < 100 * 1024 * 1024: # Sanity check: JSON header < 100MB
                return "SAFETENSORS"
    except Exception:
        pass

    return "PICKLE"

def scan_safetensors(file_path):
    """Safely extracts and scans the Safetensors JSON header for traversal/injection."""
    try:
        with open(file_path, 'rb') as f:
            header_size_bytes = f.read(8)
            header_size = struct.unpack('<Q', header_size_bytes)[0]
            
            # Prevent memory exhaustion from malformed headers
            if header_size > 10 * 1024 * 1024: 
                return True, f"Safetensors header suspiciously large: {header_size} bytes", {}
                
            header_json = f.read(header_size).decode('utf-8')
            metadata = json.loads(header_json)
            
            # Scan metadata values for path traversal and shell injection
            metadata_str = json.dumps(metadata.get("__metadata__", {})).lower()
            if any(bad in metadata_str for bad in ('../', '..\\', '/etc/passwd', 'cmd.exe', '/bin/sh')):
                return True, "Path traversal or shell injection found in Safetensors metadata", metadata
                
            return False, "Clean", metadata
    except Exception as e:
        return True, f"Safetensors parsing error (Possible malformed evasion): {str(e)}", {}

def scan_hdf5(file_path):
    """Checks for Lambda layers or custom Python bytecode in Keras architectures."""
    # We do a safe binary regex search rather than using h5py, 
    # to avoid triggering any HDF5 parser vulnerabilities.
    try:
        with open(file_path, 'rb') as f:
            data = f.read(5 * 1024 * 1024) # Scan first 5MB where architecture usually lives
            
            if b'Lambda' in data or b'CustomObject' in data:
                return True, "Potentially hostile Keras Lambda layer / Custom Object detected", {}
                
            if b'marshal' in data and b'loads' in data:
                return True, "Embedded Python marshal bytecode detected in HDF5", {}
                
        return False, "Clean", {}
    except Exception as e:
        return True, f"HDF5 read error: {str(e)}", {}

def scan_onnx(file_path):
    """Detects suspicious ONNX operators that could lead to logic bypasses."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(5 * 1024 * 1024)
            
            # Look for system calls or weird string ops embedded in the graph
            if b'System' in data or b'Command' in data or b'Exec' in data:
                return True, "Suspicious operator strings found in ONNX graph", {}
                
        return False, "Clean", {}
    except Exception as e:
        return True, f"ONNX read error: {str(e)}", {}

def scan_gguf(file_path):
    """Validates GGUF bounds to prevent Llama.cpp buffer overflows."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'GGUF':
                return True, "Invalid GGUF magic bytes", {}
                
            version = struct.unpack('<I', f.read(4))[0]
            if version > 3: # Currently only v1, v2, v3 exist
                return True, f"Unknown GGUF version {version} (Possible parser crash attempt)", {}
                
            tensor_count = struct.unpack('<Q', f.read(8))[0]
            kv_count = struct.unpack('<Q', f.read(8))[0]
            
            if tensor_count > 1000000 or kv_count > 1000000:
                return True, "GGUF tensor/KV count exceeds sanity limits (Buffer Overflow attempt)", {}
                
        return False, "Clean", {}
    except Exception as e:
        return True, f"GGUF parsing error: {str(e)}", {}
