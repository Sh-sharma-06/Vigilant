"""
Vigilant ONNX Inspector
=======================
Static scanner for ONNX models. Uses the official `onnx` package when
available (full protobuf deserialization); otherwise falls back to a
raw-bytes heuristic scan with LOW confidence.

Checks:
  * node op-types / domains against the standard ONNX operator sets
  * external_data references with directory traversal or absolute paths
  * malformed / overflowing tensor dimensions (allocation bombs)
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

FORMAT = "ONNX"
DIM_PRODUCT_LIMIT = 1 << 40        # ~1 Ti elements == allocation-bomb territory

ALLOWED_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"}

# Standard ai.onnx operator allowlist (opset <= 21). Unknown op-types in the
# default domain are flagged; anything outside ALLOWED_DOMAINS is a custom op.
STANDARD_OPS = {
    "Abs", "Acos", "Acosh", "Add", "AffineGrid", "And", "ArgMax", "ArgMin",
    "Asin", "Asinh", "Atan", "Atanh", "AveragePool", "BatchNormalization",
    "Bernoulli", "BitShift", "BitwiseAnd", "BitwiseNot", "BitwiseOr",
    "BitwiseXor", "BlackmanWindow", "Cast", "CastLike", "Ceil", "Celu",
    "CenterCropPad", "Clip", "Col2Im", "Compress", "Concat",
    "ConcatFromSequence", "Constant", "ConstantOfShape", "Conv",
    "ConvInteger", "ConvTranspose", "Cos", "Cosh", "CumSum", "DFT",
    "DeformConv", "DepthToSpace", "DequantizeLinear", "Det", "Div",
    "Dropout", "DynamicQuantizeLinear", "Einsum", "Elu", "Equal", "Erf",
    "Exp", "Expand", "EyeLike", "Flatten", "Floor", "GRU", "Gather",
    "GatherElements", "GatherND", "Gemm", "GlobalAveragePool",
    "GlobalLpPool", "GlobalMaxPool", "Greater", "GreaterOrEqual",
    "GridSample", "HammingWindow", "HannWindow", "HardSigmoid", "HardSwish",
    "Hardmax", "Identity", "If", "ImageDecoder", "InstanceNormalization",
    "IsInf", "IsNaN", "LRN", "LSTM", "LeakyRelu", "Less", "LessOrEqual",
    "Log", "LogSoftmax", "Loop", "LpNormalization", "LpPool", "MatMul",
    "MatMulInteger", "Max", "MaxPool", "MaxRoiPool", "MaxUnpool", "Mean",
    "MeanVarianceNormalization", "MelWeightMatrix", "Min", "Mish", "Mod",
    "Mul", "Multinomial", "Neg", "NonMaxSuppression", "NonZero", "Not",
    "OneHot", "Optional", "OptionalGetElement", "OptionalHasElement", "Or",
    "PRelu", "Pad", "Pow", "QLinearConv", "QLinearMatMul",
    "QuantizeLinear", "RNN", "RandomNormal", "RandomNormalLike",
    "RandomUniform", "RandomUniformLike", "Range", "Reciprocal",
    "ReduceL1", "ReduceL2", "ReduceLogSum", "ReduceLogSumExp", "ReduceMax",
    "ReduceMean", "ReduceMin", "ReduceProd", "ReduceSum", "ReduceSumSquare",
    "RegexFullMatch", "Relu", "Resize", "ReverseSequence", "RoiAlign",
    "Round", "STFT", "Scan", "Scatter", "ScatterElements", "ScatterND",
    "Selu", "SequenceAt", "SequenceConstruct", "SequenceEmpty",
    "SequenceErase", "SequenceInsert", "SequenceLength", "SequenceMap",
    "Shape", "Shrink", "Sigmoid", "Sign", "Sin", "Sinh", "Size", "Slice",
    "Softmax", "SoftmaxCrossEntropyLoss", "Softplus", "Softsign",
    "SpaceToDepth", "Split", "SplitToSequence", "Sqrt", "Squeeze",
    "StringNormalizer", "Sub", "Sum", "Tan", "Tanh", "TfIdfVectorizer",
    "ThresholdedRelu", "Tile", "TopK", "Transpose", "Trilu", "Unique",
    "Unsqueeze", "Upsample", "Where", "Xor",
}
# ai.onnx.ml operators are classic-ML transforms — allowed but noted.
_ML_DOMAIN = "ai.onnx.ml"
_TRAVERSAL_RE = re.compile(r"(\.\.[\\/])|(^[\\/])|(^[A-Za-z]:[\\/])")


def _report(model_name: str, verdict: str, confidence: str, attack_vector: str,
            summary: str, **details: Any) -> Dict[str, Any]:
    return {
        "model_name": model_name, "format": FORMAT, "verdict": verdict,
        "confidence": confidence, "attack_vector": attack_vector,
        "summary": summary, "technical_details": details,
    }


def _fallback_scan(path: str) -> Dict[str, Any]:
    """Heuristic raw-bytes scan when the onnx package is unavailable."""
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        data = fh.read()
    hits = []
    if b"external_data" in data:
        hits.append("references external_data")
    for m in re.finditer(rb"\.\.[\\/]", data):
        hits.append(f"traversal sequence at offset {m.start()}")
    if hits:
        return _report(name, "SUSPICIOUS", "LOW", "PATH_TRAVERSAL",
                       "onnx package unavailable; raw scan found: "
                       + "; ".join(hits), engine="raw-fallback", hits=hits)
    return _report(name, "BENIGN", "LOW", "NONE",
                   "onnx package unavailable; raw scan found no traversal "
                   "or external-data markers.", engine="raw-fallback")


def scan_onnx(path: str) -> Dict[str, Any]:
    """Statically inspect an .onnx model. Returns Vigilant telemetry."""
    name = os.path.basename(path)
    try:
        import onnx  # type: ignore
    except ImportError:
        try:
            return _fallback_scan(path)
        except OSError as exc:
            return _report(name, "SUSPICIOUS", "LOW", "NONE",
                           f"Unreadable file: {exc}", error=str(exc))

    try:
        model = onnx.load(path, load_external_data=False)
    except Exception as exc:  # protobuf decode failure etc.
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"ONNX protobuf failed to parse: {exc}",
                       error=str(exc))

    custom_ops: List[str] = []
    deprecated_ops: List[str] = []
    external_hits: List[str] = []
    dim_hits: List[str] = []

    graph = model.graph

    # ---- graph & operator audit --------------------------------------- #
    for node in graph.node:
        domain = node.domain or ""
        label = f"{domain}::{node.op_type}" if domain else node.op_type
        if domain not in ALLOWED_DOMAINS:
            custom_ops.append(f"{label} (node '{node.name}') — unrecognized domain")
        elif domain in ("", "ai.onnx") and node.op_type not in STANDARD_OPS:
            custom_ops.append(f"{label} (node '{node.name}') — non-standard op-type")
        if node.op_type in {"Experimental"}:
            deprecated_ops.append(label)

    # ---- external data injection --------------------------------------- #
    def _check_external(tensor, where: str) -> None:
        if tensor.data_location == onnx.TensorProto.EXTERNAL or tensor.external_data:
            for entry in tensor.external_data:
                if entry.key == "location":
                    loc = entry.value
                    if _TRAVERSAL_RE.search(loc):
                        external_hits.append(f"{where}: malicious location '{loc}'")
                    else:
                        external_hits.append(f"{where}: external reference '{loc}'")

    for init in graph.initializer:
        _check_external(init, f"initializer '{init.name}'")
    for sparse in graph.sparse_initializer:
        _check_external(sparse.indices, f"sparse '{sparse.dims}' indices")
        _check_external(sparse.values, "sparse values")

    # ---- malformed dimensions / allocation bombs ------------------------ #
    def _check_dims(dims, where: str) -> None:
        product = 1
        for d in dims:
            if d.dim_value < 0:
                dim_hits.append(f"{where}: negative dimension {d.dim_value}")
                return
            if d.dim_value:
                product *= d.dim_value
            if product > DIM_PRODUCT_LIMIT:
                dim_hits.append(f"{where}: dimension product exceeds 2^40")
                return

    for vi in list(graph.value_info) + list(graph.input) + list(graph.output):
        if vi.type.HasField("tensor_type"):
            _check_dims(vi.type.tensor_type.shape.dim, f"value_info '{vi.name}'")
    for init in graph.initializer:
        product = 1
        for d in init.dims:
            if d < 0:
                dim_hits.append(f"initializer '{init.name}': negative dim {d}")
                break
            product *= max(d, 1)
            if product > DIM_PRODUCT_LIMIT:
                dim_hits.append(f"initializer '{init.name}': dim product > 2^40")
                break

    details = dict(
        ir_version=model.ir_version,
        opset_imports={o.domain or "ai.onnx": o.version
                       for o in model.opset_import},
        node_count=len(graph.node), initializer_count=len(graph.initializer),
        custom_operators=custom_ops, deprecated_operators=deprecated_ops,
        external_data_references=external_hits, dimension_anomalies=dim_hits,
    )

    malicious_external = [h for h in external_hits if "malicious" in h]
    if malicious_external:
        return _report(name, "MALICIOUS", "HIGH", "PATH_TRAVERSAL",
                       "External-data references escape the model directory "
                       "(traversal / absolute path).", **details)
    if dim_hits:
        return _report(name, "MALICIOUS", "HIGH", "DOS_BOMB",
                       "Tensor dimensions are malformed or imply impossible "
                       "allocations (allocation bomb).", **details)
    if custom_ops or deprecated_ops:
        return _report(name, "SUSPICIOUS", "MEDIUM", "NONE",
                       f"{len(custom_ops)} custom/unrecognized operators, "
                       f"{len(deprecated_ops)} deprecated operators.",
                       **details)
    return _report(name, "BENIGN", "HIGH", "NONE",
                   f"Clean ONNX graph: {len(graph.node)} nodes, all ops "
                   f"standard, no external data anomalies.", **details)


if __name__ == "__main__":
    import sys
    print(json.dumps(scan_onnx(sys.argv[1]), indent=2, default=str))
