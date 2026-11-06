"""Validated configuration; credential values are resolved only from environment."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

USER_TYPES = ("normal", "tenanted", "account-root", "account-user", "ldap", "sts")
BUCKET_STATES = ("normal", "versioned", "suspended")


@dataclass(frozen=True)
class Credentials:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str | None = field(default=None, repr=False)
    tenant: str | None = None

    @classmethod
    def from_env(cls, prefix):
        access = os.getenv(f"{prefix}_ACCESS_KEY_ID")
        secret = os.getenv(f"{prefix}_SECRET_ACCESS_KEY")
        if not access or not secret:
            raise ValueError(
                f"Set {prefix}_ACCESS_KEY_ID and {prefix}_SECRET_ACCESS_KEY"
            )
        return cls(
            access,
            secret,
            os.getenv(f"{prefix}_SESSION_TOKEN"),
            os.getenv(f"{prefix}_TENANT"),
        )


@dataclass(frozen=True)
class Config:
    endpoint: str = "http://127.0.0.1:7480"
    region: str = "us-east-1"
    verify_tls: bool | str = True
    user_types: tuple = ("normal", "tenanted", "account-root", "account-user")
    bucket_states: tuple = BUCKET_STATES
    identities: dict = field(default_factory=dict, repr=False)
    admin_command: tuple = ("radosgw-admin",)
    objects: int = 20
    object_size: int = 4096
    multipart_part_size: int = 5 * 1024 * 1024
    workers: int = 4
    timeout: int = 300
    poll_interval: int = 2
    request_timeout: int = 30
    lifecycle_days: int = 1
    shards: int = 11
    features: tuple = ()
    optional_tools: tuple = ()
    notification: dict = field(default_factory=dict)


def load_config(path=None):
    try:
        raw = {} if path is None else yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError:
        raise ValueError("Invalid YAML configuration") from None
    if not isinstance(raw, dict):
        raise ValueError("Configuration must be a YAML mapping")
    if not all(isinstance(key, str) for key in raw):
        raise ValueError("Configuration keys must be strings")
    unknown = set(raw) - set(Config.__dataclass_fields__)
    if unknown:
        raise ValueError(f"Unknown configuration keys: {sorted(unknown)}")
    for key in (
        "user_types",
        "bucket_states",
        "features",
        "admin_command",
        "optional_tools",
    ):
        if key in raw:
            if not isinstance(raw[key], list):
                raise ValueError(f"{key} must be a list")
            raw[key] = tuple(raw[key])
    cfg = Config(**raw)
    if (
        not isinstance(cfg.endpoint, str)
        or not isinstance(cfg.region, str)
        or not cfg.region
    ):
        raise ValueError("endpoint and region must be nonempty strings")
    try:
        endpoint = urlparse(cfg.endpoint)
        endpoint.port
    except ValueError:
        raise ValueError("Invalid endpoint URL or port") from None
    if endpoint.scheme not in ("http", "https") or not endpoint.hostname:
        raise ValueError("endpoint must be an HTTP(S) URL")
    if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError("endpoint must not contain credentials, query, or fragment")
    if not isinstance(cfg.verify_tls, (bool, str)) or cfg.verify_tls == "":
        raise ValueError("verify_tls must be a boolean or CA bundle path")
    for key in (
        "objects",
        "object_size",
        "multipart_part_size",
        "workers",
        "timeout",
        "poll_interval",
        "request_timeout",
        "lifecycle_days",
        "shards",
    ):
        value = getattr(cfg, key)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if cfg.multipart_part_size < 5 * 1024 * 1024:
        raise ValueError("multipart_part_size must be at least 5 MiB")
    for key, allowed in (
        ("user_types", USER_TYPES),
        ("bucket_states", BUCKET_STATES),
        ("features", ("lifecycle", "gc", "notifications", "resharding")),
        ("optional_tools", ("awscli", "elbencho")),
    ):
        values = getattr(cfg, key)
        if not all(isinstance(v, str) and v in allowed for v in values):
            raise ValueError(f"Invalid {key}; allowed: {allowed}")
        if key not in ("features", "optional_tools") and not values:
            raise ValueError(f"{key} must not be empty")
    if not cfg.admin_command or not all(
        isinstance(v, str) and v for v in cfg.admin_command
    ):
        raise ValueError("admin_command must be a nonempty argv list")
    if not isinstance(cfg.identities, dict) or not isinstance(cfg.notification, dict):
        raise ValueError("identities and notification must be mappings")
    for kind, prefix in cfg.identities.items():
        if kind not in USER_TYPES or not isinstance(prefix, str) or not prefix:
            raise ValueError("identities maps user types to environment prefixes")
    if "notifications" in cfg.features:
        required = {"bind_host", "advertise_host"}
        if set(cfg.notification) != required or not all(
            isinstance(v, str) and v and "/" not in v and ":" not in v
            for v in cfg.notification.values()
        ):
            raise ValueError(
                "notification requires bind_host and advertise_host (IPv4 or DNS)"
            )
    return cfg
