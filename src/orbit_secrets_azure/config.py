# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Validated Azure Key Vault address and request limits."""

from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


class AzureSecretsConfig(BaseModel):
    """Bounded Key Vault configuration; credentials come from an async identity chain."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, validate_default=True)

    vault_url: StrictStr = Field(min_length=1, max_length=2_048)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_concurrency: StrictInt = Field(default=8, ge=1, le=128)

    @field_validator("vault_url")
    @classmethod
    def validate_vault_url(cls, value: str) -> str:
        """Require an HTTPS origin and reject embedded credentials, query, and fragment data."""
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.query == ""
                and parsed.fragment == ""
                and parsed.path in {"", "/"}
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("vault_url must be an HTTPS Key Vault origin without credentials.")
        return value.rstrip("/")
