"""Company-neutral repository lint engine."""

from .engine import analyze, check_baseline
from .errors import ConfigurationError
from .inspection import ProjectCoordinate, parse_project_metadata
from .models import (
    AnalysisReport,
    Component,
    Dependency,
    Diagnostic,
    ExecutionIssue,
    Manifest,
    Policy,
    Rule,
)
from .parser import load_baseline, load_manifest
from .registry import POLICY_API_VERSION, PolicyRegistry


__all__ = [
    "POLICY_API_VERSION",
    "AnalysisReport",
    "Component",
    "ConfigurationError",
    "Dependency",
    "Diagnostic",
    "ExecutionIssue",
    "Manifest",
    "Policy",
    "PolicyRegistry",
    "ProjectCoordinate",
    "Rule",
    "analyze",
    "check_baseline",
    "load_baseline",
    "load_manifest",
    "parse_project_metadata",
]
