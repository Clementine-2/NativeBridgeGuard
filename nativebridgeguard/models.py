from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


@dataclass
class BrowserExtension:
    browser: str
    profile: str
    extension_id: str
    name: str
    version: str
    manifest_path: str
    permissions: list[str] = field(default_factory=list)

    @property
    def has_native_messaging(self) -> bool:
        return "nativeMessaging" in self.permissions


@dataclass
class RegistryHost:
    browser_family: str
    scope: str
    view: str
    host_name: str
    registry_key: str
    manifest_path: str


@dataclass
class BrowserPolicy:
    browser: str
    allowlist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    user_level_hosts_enabled: bool | None = None


@dataclass
class BinaryEvidence:
    path: str
    exists: bool
    sha256: str | None = None
    signature_status: str | None = None
    signer: str | None = None
    owner: str | None = None
    acl: str | None = None
    parent_acl: str | None = None
    writable_hint_reason: str | None = None
    current_user_writable_hint: bool | None = None
    under_user_profile: bool | None = None


@dataclass
class NativeHostManifest:
    name: str
    description: str | None
    manifest_path: str
    binary_path: str | None
    allowed_origins: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustPath:
    browser: str
    host_name: str
    effective_registration: RegistryHost
    shadowed_registrations: list[RegistryHost]
    manifest: NativeHostManifest | None
    binary: BinaryEvidence | None
    allowed_extension_ids: list[str]
    installed_allowed_extensions: list[BrowserExtension]
    missing_allowed_extension_ids: list[str]
    policy_status: str
    policy_reason: str | None


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    trust_key: str
    evidence: list[str]
    interpretation: str


@dataclass
class Snapshot:
    schema_version: int
    created_at: str
    host: str
    extensions: list[BrowserExtension]
    registrations: list[RegistryHost]
    policies: list[BrowserPolicy]
    trust_paths: list[TrustPath]
    findings: list[Finding]
    collection_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Event:
    """Machine-readable security event emitted by the stateful monitor.

    One event corresponds to one stable semantic trust-drift signal. The
    Markdown alert is only a human-readable presentation of these events; the
    NDJSON stream is the authoritative machine interface.
    """

    schema_version: int
    timestamp: str
    event_type: str
    severity: str
    trust_key: str
    summary: str
    before: Any = None
    after: Any = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
