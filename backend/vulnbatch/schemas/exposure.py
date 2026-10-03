"""Bounded, offline service graph edits. Every identity and mapping is explicit."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NodeKind = Literal["host", "device", "load_balancer", "vip", "service", "endpoint"]
RelationshipKind = Literal["endpoint_of", "backed_by", "routes_to", "hosted_on", "management_of"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def bounded_json(self) -> Self:
        try:
            encoded = json.dumps(self.model_dump(mode="json"), allow_nan=False, ensure_ascii=True)
        except (ValueError, RecursionError) as exc:
            raise ValueError("Evidence must be finite, bounded JSON") from exc
        if "\\u0000" in encoded:
            raise ValueError("Exposure text cannot contain NUL characters")
        if len(encoded.encode()) > 4 * 1024 * 1024:
            raise ValueError("Exposure envelope exceeds 4 MiB of expanded evidence")
        return self


class NodeInput(Contract):
    ref: str = Field(min_length=1, max_length=128, pattern=r"\S")
    native_id: str = Field(min_length=1, max_length=512, pattern=r"\S")
    kind: NodeKind
    label: str = Field(min_length=1, max_length=255, pattern=r"\S")
    asset_id: uuid.UUID | None = None
    protocol: str | None = Field(default=None, max_length=32)
    port: int | None = Field(default=None, ge=0, le=65535)
    dns_name: str | None = Field(default=None, max_length=255)
    sni: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    network_scope: str | None = Field(default=None, max_length=128)
    facts: dict[str, Any] = Field(default_factory=dict)
    active: bool = True
    expected_version: int | None = Field(default=None, ge=1)

    @field_validator("ip_address")
    @classmethod
    def ip_literal(cls, value: str | None) -> str | None:
        if value is not None:
            ipaddress.ip_address(value)
        return value


class RelationshipInput(Contract):
    kind: RelationshipKind
    from_node: str = Field(min_length=1, max_length=128)
    to_node: str = Field(min_length=1, max_length=128)
    active: bool = True
    expected_version: int | None = Field(default=None, ge=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttributionInput(Contract):
    observation_id: uuid.UUID
    node_ref: str | None = Field(default=None, min_length=1, max_length=128)
    status: Literal["attributed", "review_needed"]
    reason: str = Field(min_length=1, max_length=2000, pattern=r"\S")
    expected_version: int | None = Field(default=None, ge=1)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def mapping_status(self) -> Self:
        if (self.status == "attributed") != (self.node_ref is not None):
            raise ValueError("Only explicit attributed mappings have a node_ref")
        return self


class GraphEnvelope(Contract):
    intent: Literal["source_facts", "manual_correction"] = "source_facts"
    source: str = Field(min_length=1, max_length=64, pattern=r"\S")
    instance: str = Field(min_length=1, max_length=128, pattern=r"\S")
    observed_at: datetime | None = None
    source_version: str | None = Field(default=None, max_length=128)
    time_meaning: Literal["source_observed", "export_generated", "unknown"] = "unknown"
    nodes: list[NodeInput] = Field(default_factory=list, max_length=2000)
    relationships: list[RelationshipInput] = Field(default_factory=list, max_length=4000)
    attributions: list[AttributionInput] = Field(default_factory=list, max_length=2000)

    @model_validator(mode="after")
    def unique_references(self) -> Self:
        if not self.nodes and not self.relationships and not self.attributions:
            raise ValueError("Supply at least one explicit graph change")
        if self.observed_at is not None and self.observed_at.tzinfo is None:
            raise ValueError("observed_at must have an explicit timezone")
        if len({node.ref for node in self.nodes}) != len(self.nodes):
            raise ValueError("Node refs must be unique")
        if len({node.native_id for node in self.nodes}) != len(self.nodes):
            raise ValueError("Native IDs must be unique within a source instance")
        edges = [(edge.kind, edge.from_node, edge.to_node) for edge in self.relationships]
        if len(set(edges)) != len(edges):
            raise ValueError("Duplicate relationships are not supported")
        if len({item.observation_id for item in self.attributions}) != len(self.attributions):
            raise ValueError("Supply each observation attribution once")
        return self


class PreviewRequest(Contract):
    graph: GraphEnvelope


class ApplyRequest(PreviewRequest):
    request_key: str = Field(min_length=1, max_length=160, pattern=r"\S")
    reason: str = Field(min_length=1, max_length=2000, pattern=r"\S")
    expected_revision: int = Field(ge=0)
    preview_token: str | None = Field(default=None, max_length=2048)
    confirmed: bool = False

    @model_validator(mode="after")
    def explicit_review(self) -> Self:
        if not self.preview_token and not self.confirmed:
            raise ValueError("Supply a preview_token or explicit confirmed=true")
        return self


class UndoRequest(Contract):
    decision_id: uuid.UUID
    request_key: str = Field(min_length=1, max_length=160, pattern=r"\S")
    reason: str = Field(min_length=1, max_length=2000, pattern=r"\S")
    expected_revision: int = Field(ge=0)
    confirmed: Literal[True]
