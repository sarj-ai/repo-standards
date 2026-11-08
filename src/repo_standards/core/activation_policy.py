"""Protected-base configuration for the opt-in nonproduction activation lane."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ActivationEdit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    environment: Literal["dev", "preview"]
    path: str = Field(min_length=1, max_length=512)
    before: str = Field(min_length=1, max_length=4096)
    after: str = Field(min_length=1, max_length=4096)


class RegisteredActivation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    feature_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    ticket: str = Field(pattern=r"^[A-Z]+-[1-9][0-9]*$")
    kind: Literal["rollout"]
    edits: list[ActivationEdit] = Field(min_length=1, max_length=16)


class ActivationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    author: str = Field(pattern=r"^[a-z0-9-]+\[bot\]$")
    app_id: Literal[15368]
    workflow_path: str = Field(pattern=r"^\.github/workflows/[a-zA-Z0-9_-]+\.ya?ml$")
    workflow_ref: Literal["refs/heads/dev"]
    event: Literal["workflow_dispatch"]
    artifact_name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,128}$")
    features: list[RegisteredActivation] = Field(min_length=1, max_length=128)
