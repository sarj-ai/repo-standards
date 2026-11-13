from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator


class _ActivationEdit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    environment: Literal["dev", "preview"]
    path: str = Field(min_length=1, max_length=512)
    after: str = Field(min_length=1, max_length=4096)


class ReplacementActivationEdit(_ActivationEdit):
    operation: Literal["replace"] = "replace"
    before: str = Field(min_length=1, max_length=4096)


class AppendActivationEdit(_ActivationEdit):
    operation: Literal["append_line"] = "append_line"
    before: Literal[""] = ""

    @model_validator(mode="after")
    def single_line(self) -> Self:
        if any(c in self.after for c in "\r\n"):
            message = "append_line requires a single registered line"
            raise ValueError(message)
        return self


class ActivationEdit(
    RootModel[
        Annotated[
            ReplacementActivationEdit | AppendActivationEdit,
            Field(discriminator="operation"),
        ]
    ]
):
    model_config = ConfigDict(frozen=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def default_operation(cls, value: object) -> object:
        unchanged: object = value
        if isinstance(value, dict) and "operation" not in value:
            return ReplacementActivationEdit.model_validate(value)
        return unchanged

    @property
    def environment(self) -> Literal["dev", "preview"]:
        return self.root.environment

    @property
    def path(self) -> str:
        return self.root.path

    @property
    def operation(self) -> Literal["replace", "append_line"]:
        return self.root.operation

    @property
    def before(self) -> str:
        return self.root.before

    @property
    def after(self) -> str:
        return self.root.after


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
