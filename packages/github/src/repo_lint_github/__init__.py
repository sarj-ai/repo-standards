"""Read-only GitHub CI/CD evidence collection and policy analysis."""

from .analyzer import DeliveryConfiguration, analyze
from .client import GitHubClient
from .models import (
    ActionReference,
    BranchEvidence,
    GitHubAnalysisReport,
    RepositoryEvidence,
    RulesetEvidence,
    WorkflowDocument,
    WorkflowInspection,
)
from .workflows import inspect_workflow, inspect_workflows


__all__ = [
    "ActionReference",
    "BranchEvidence",
    "DeliveryConfiguration",
    "GitHubAnalysisReport",
    "GitHubClient",
    "RepositoryEvidence",
    "RulesetEvidence",
    "WorkflowDocument",
    "WorkflowInspection",
    "analyze",
    "inspect_workflow",
    "inspect_workflows",
]
