"""
Breakpoint Defense module — the blue-team counterpart to the attack algorithms.

  from breakpoint.defense import scan_input, classify_output, ShieldedAdapter

Composable layers:
  scanner.py   — input prompt scanning (pattern + heuristic)
  classifier.py — output jailbreak classification
  shield.py    — adapter wrapper that enforces both layers
"""
from breakpoint.defense.scanner import scan_input, ScanResult, ScanFlag
from breakpoint.defense.classifier import classify_output, ClassifyResult
from breakpoint.defense.shield import ShieldedAdapter

__all__ = [
    "scan_input", "ScanResult", "ScanFlag",
    "classify_output", "ClassifyResult",
    "ShieldedAdapter",
]
