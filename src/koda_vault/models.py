"""Pydantic models for the credential vault.

SECURITY RULE: The CredentialMeta model intentionally excludes the credential value.
The decrypted value is ONLY returned by CredentialVault.retrieve_credential() and
must NEVER appear in API responses, logs, or error messages.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class CredentialScope(str, Enum):
    """Permission scopes for credential access.

    Format: service:action
    Agent tasks must declare which scope they need. The vault checks
    before returning the decrypted value.
    """

    # Gmail
    GMAIL_READ = "gmail:read"
    GMAIL_SEND = "gmail:send"
    GMAIL_DELETE = "gmail:delete"
    GMAIL_MANAGE = "gmail:manage"

    # Google Calendar
    GCAL_READ = "gcal:read"
    GCAL_WRITE = "gcal:write"
    GCAL_DELETE = "gcal:delete"

    # Slack
    SLACK_READ = "slack:read"
    SLACK_SEND = "slack:send"
    SLACK_MANAGE = "slack:manage"

    # Discord
    DISCORD_READ = "discord:read"
    DISCORD_SEND = "discord:send"

    # GitHub
    GITHUB_READ = "github:read"
    GITHUB_WRITE = "github:write"
    GITHUB_ADMIN = "github:admin"

    # AI Models
    LLM_QUERY = "llm:query"
    LLM_ADMIN = "llm:admin"

    # File System
    FS_READ = "fs:read"
    FS_WRITE = "fs:write"
    FS_DELETE = "fs:delete"

    # Shell
    SHELL_EXECUTE = "shell:execute"
    SHELL_INSTALL = "shell:install"
    SHELL_NETWORK = "shell:network"

    # Generic (for custom integrations)
    CUSTOM_READ = "custom:read"
    CUSTOM_WRITE = "custom:write"
    CUSTOM_DELETE = "custom:delete"
    CUSTOM_ADMIN = "custom:admin"


class CredentialCreate(BaseModel):
    """Input model for storing a new credential."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable name (e.g., 'work-gmail')",
    )
    service: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Service identifier (e.g., 'gmail', 'slack', 'anthropic')",
    )
    scopes: list[str] = Field(
        ...,
        min_length=1,
        description="Permission scopes for this credential",
    )
    value: str = Field(
        ...,
        min_length=1,
        description="The credential value (API key, token, etc.)",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "work-gmail",
                    "service": "gmail",
                    "scopes": ["gmail:read", "gmail:send"],
                    "value": "ya29.a0AXooCg...",
                }
            ]
        }
    }


class CredentialMeta(BaseModel):
    """Credential metadata — returned by list and detail endpoints.

    SECURITY: This model intentionally has NO value field.
    """

    id: str
    name: str
    service: str
    scopes: list[str]
    created_at: datetime
    last_accessed: datetime | None = None
    last_accessed_by: str | None = None


class CredentialListItem(BaseModel):
    """Minimal credential info for list endpoints. No scopes, no values."""

    id: str
    name: str
    service: str
    created_at: datetime
    last_accessed: datetime | None = None
