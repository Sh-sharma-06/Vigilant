#!/usr/bin/env python3
"""
Vigilant Priority 2: Graph-Aware TensorFlow SavedModel (.pb) Protobuf Scanner
Zero external dependencies (does not require TensorFlow or protobuf wheels).
Strictly parses Protobuf wire format for:
  SavedModel (field 2: meta_graphs)
    -> MetaGraphDef (field 2: graph_def)
      -> GraphDef (field 1: node [NodeDef], field 2: library [FunctionDefLibrary])
        -> FunctionDefLibrary (field 1: function [FunctionDef])
          -> FunctionDef (field 1: signature.name, field 3: node_def [NodeDef])
            -> NodeDef (field 1: name, field 2: op, field 3: input)
Only flags actual wired GraphDef/FunctionDef NodeDef.op entries — eliminates
false positives from docstrings, variable names, or Const string tensors.
"""
from pathlib import Path

DANGEROUS_OPS = {
    "PyFunc": "Executes arbitrary Python callback at inference time",
    "PyFuncStateless": "Executes arbitrary stateless Python callback at inference time",
    "EagerPyFunc": "Executes arbitrary eager Python function at inference time",
    "ReadFile": "Direct host filesystem read (exfiltration primitive)",
    "WriteFile": "Direct host filesystem write (tampering/persistence primitive)",
    "MatchingFiles": "Filesystem glob enumeration (reconnaissance primitive)",
    "Save": "Arbitrary checkpoint filesystem write",
    "SaveV2": "Arbitrary checkpoint filesystem write",
    "Restore": "Arbitrary filesystem read during graph execution",
    "RestoreV2": "Arbitrary filesystem read during graph execution",
}

HIGH_RISK_OPS = {"PyFunc", "PyFuncStateless", "EagerPyFunc", "ReadFile", "WriteFile", "MatchingFiles"}


def _read_varint(buf: memoryview, pos: int, end: int):
    result = 0
    shift = 0
    while pos < end:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 64:
            raise ValueError("Malformed protobuf varint")
    raise ValueError("Truncated protobuf varint")


def _iter_fields(buf: memoryview, start: int = 0, end: int | None = None):
    if end is None:
        end = len(buf)
    pos = start
    while pos < end:
        tag, pos = _read_varint(buf, pos, end)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            val, pos = _read_varint(buf, pos, end)
            yield field_num, wire_type, val
        elif wire_type == 1:  # 64-bit
            if pos + 8 > end:
                break
            yield field_num, wire_type, buf[pos : pos + 8]
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(buf, pos, end)
            if pos + length > end:
                break
            yield field_num, wire_type, buf[pos : pos + length]
            pos += length
        elif wire_type == 5:  # 32-bit
            if pos + 4 > end:
                break
            yield field_num, wire_type, buf[pos : pos + 4]
            pos += 4
        else:
            # Unsupported legacy group wire types (3/4) — stop this submessage safely
            break


def _parse_node_def(buf: memoryview) -> dict:
    name = ""
    op = ""
    inputs = []
    for fnum, wtype, val in _iter_fields(buf):
        if wtype == 2:
            if fnum == 1:
                name = bytes(val).decode("utf-8", errors="replace")
            elif fnum == 2:
                op = bytes(val).decode("utf-8", errors="replace")
            elif fnum == 3:
                inputs.append(bytes(val).decode("utf-8", errors="replace"))
    return {"name": name, "op": op, "inputs": inputs}


def _parse_function_def(buf: memoryview) -> tuple[str, list[dict]]:
    fn_name = "<anonymous_fn>"
    nodes = []
    for fnum, wtype, val in _iter_fields(buf):
        if wtype == 2:
            if fnum == 1:  # OpDef signature -> field 1 is name
                for sfnum, swtype, sval in _iter_fields(val):
                    if sfnum == 1 and swtype == 2:
                        fn_name = bytes(sval).decode("utf-8", errors="replace")
                        break
            elif fnum == 3:  # repeated NodeDef node_def
                nodes.append(_parse_node_def(val))
    return fn_name, nodes


def _parse_graph_def(buf: memoryview, scope_prefix: str, findings: list, stats: dict):
    for fnum, wtype, val in _iter_fields(buf):
        if wtype != 2:
            continue
        if fnum == 1:  # repeated NodeDef node
            node = _parse_node_def(val)
            stats["nodes_inspected"] += 1
            op = node["op"]
            if op in HIGH_RISK_OPS:
                findings.append({
                    "severity": "MALICIOUS",
                    "op": op,
                    "location": f"{scope_prefix}/{node['name'] or '<unnamed>'}",
                    "inputs": node["inputs"][:5],
                    "detail": f"Wired TensorFlow op '{op}': {DANGEROUS_OPS[op]}",
                })
        elif fnum == 2:  # FunctionDefLibrary library
            for lfnum, lwtype, lval in _iter_fields(val):
                if lfnum == 1 and lwtype == 2:  # repeated FunctionDef function
                    fn_name, fn_nodes = _parse_function_def(lval)
                    stats["functions_inspected"] += 1
                    for node in fn_nodes:
                        stats["nodes_inspected"] += 1
                        op = node["op"]
                        if op in HIGH_RISK_OPS:
                            findings.append({
                                "severity": "MALICIOUS",
                                "op": op,
                                "location": f"{scope_prefix}/FunctionDef:{fn_name}/{node['name'] or '<unnamed>'}",
                                "inputs": node["inputs"][:5],
                                "detail": f"Wired TF FunctionDef op '{op}': {DANGEROUS_OPS[op]}",
                            })


def scan_savedmodel_bytes(raw: bytes) -> dict:
    mv = memoryview(raw)
    findings = []
    stats = {"meta_graphs": 0, "functions_inspected": 0, "nodes_inspected": 0}
    try:
        for fnum, wtype, val in _iter_fields(mv):
            if fnum == 2 and wtype == 2:  # repeated MetaGraphDef meta_graphs
                mg_idx = stats["meta_graphs"]
                stats["meta_graphs"] += 1
                for mfnum, mwtype, mval in _iter_fields(val):
                    if mfnum == 2 and mwtype == 2:  # GraphDef graph_def
                        _parse_graph_def(mval, f"MetaGraph[{mg_idx}]", findings, stats)

        # Fallback: if file is a raw frozen GraphDef (.pb) rather than wrapped SavedModel
        if stats["meta_graphs"] == 0 and stats["nodes_inspected"] == 0:
            _parse_graph_def(mv, "FrozenGraphDef", findings, stats)

        verdict = "MALICIOUS" if findings else "BENIGN"
        return {
            "ok": True,
            "parser": "protobuf_graphdef_v1",
            "verdict": verdict,
            "dangerous_ops": sorted({f["op"] for f in findings}),
            "findings": findings,
            "stats": stats,
        }
    except Exception as e:
        return {
            "ok": False,
            "parser": "protobuf_graphdef_v1",
            "verdict": "SUSPICIOUS",
            "error": str(e),
            "dangerous_ops": [],
            "findings": [],
            "stats": stats,
        }


def scan_savedmodel(path: str | Path) -> dict:
    return scan_savedmodel_bytes(Path(path).read_bytes())


# --- Built-in Self-Test (False-Positive Control + Positive Control) ---
if __name__ == "__main__":
    def _varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _ld(fnum: int, payload: bytes) -> bytes:
        return _varint((fnum << 3) | 2) + _varint(len(payload)) + payload

    # Test 1: Benign Const node whose NAME contains decoy "PyFunc_ReadFile_Test"
    benign_node = _ld(1, b"My_PyFunc_ReadFile_Decoy_Const") + _ld(2, b"Const")
    benign_pb = _ld(2, _ld(2, _ld(1, benign_node)))
    r1 = scan_savedmodel_bytes(benign_pb)
    assert r1["verdict"] == "BENIGN" and len(r1["findings"]) == 0, f"FP test failed: {r1}"
    print(f"[PASS] False-Positive Control (decoy 'PyFunc' in node name): verdict={r1['verdict']} | nodes={r1['stats']['nodes_inspected']}")

    # Test 2: Real malicious EagerPyFunc inside a TF2 FunctionDef
    mal_node = _ld(1, b"pwn_callback") + _ld(2, b"EagerPyFunc") + _ld(3, b"input_tensor:0")
    fn_def = _ld(1, _ld(1, b"__inference_serve_123")) + _ld(3, mal_node)
    mal_pb = _ld(2, _ld(2, _ld(2, _ld(1, fn_def))))
    r2 = scan_savedmodel_bytes(mal_pb)
    assert r2["verdict"] == "MALICIOUS" and r2["dangerous_ops"] == ["EagerPyFunc"], f"Positive control failed: {r2}"
    print(f"[PASS] Positive Control (wired EagerPyFunc in FunctionDef): verdict={r2['verdict']} | location={r2['findings'][0]['location']}")
