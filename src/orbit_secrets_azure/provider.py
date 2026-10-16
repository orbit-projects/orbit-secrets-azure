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
"""Async Azure Key Vault access with workload identity and explicit cleanup."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Protocol, cast

from orbit_secrets import (
    MAX_SECRET_BYTES,
    SecretAccessDeniedError,
    SecretError,
    SecretNotFoundError,
    SecretOperationError,
    SecretProviderClosedError,
    SecretReference,
    SecretUnavailableError,
    SecretValue,
    SecretVersionNotFoundError,
)

from orbit_secrets_azure.config import AzureSecretsConfig

_SECRET_NAME = re.compile(r"[A-Za-z0-9-]{1,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9-]{1,64}\Z")


class _Credential(Protocol):
    async def close(self) -> None:
        """Release the asynchronous identity credential's owned resources."""


class _VaultClient(Protocol):
    async def get_secret(self, name: str, version: str | None = None) -> Any:
        """Return a secret value and properties from Key Vault."""

    async def close(self) -> None:
        """Close the provider-owned async vault transport."""


class AzureSecretsProvider:
    """Resolve Azure Key Vault values with ``DefaultAzureCredential`` by default.

    The async credential and client are created lazily. Concurrent operations are bounded, and
    ``aclose`` blocks new work and drains in-flight reads before closing both resources.
    """

    def __init__(
        self,
        config: AzureSecretsConfig,
        *,
        credential_factory: Callable[[], _Credential] | None = None,
        client_factory: Callable[[str, _Credential], _VaultClient] | None = None,
    ) -> None:
        """Prepare the provider without resolving credentials or opening network connections."""
        if not isinstance(config, AzureSecretsConfig):
            raise TypeError("config must be an AzureSecretsConfig.")
        self.config = config
        self._credential_factory = credential_factory or _default_credential_factory
        self._client_factory = client_factory or _default_client_factory
        self._credential: _Credential | None = None
        self._client: _VaultClient | None = None
        self._client_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._condition = asyncio.Condition()
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._active = 0
        self._closing = False
        self._closed = False

    async def _get_client(self) -> _VaultClient:
        """Create and retain the credential and async client as a single owned resource pair."""
        async with self._client_lock:
            if self._client is None:
                credential = self._credential_factory()
                try:
                    client = self._client_factory(self.config.vault_url, credential)
                except BaseException:
                    try:
                        result = credential.close()
                        if inspect.isawaitable(result):
                            await result
                    except BaseException:
                        self._credential = credential
                    raise
                self._credential = credential
                self._client = client
            return self._client

    @asynccontextmanager
    async def _use_client(self) -> AsyncIterator[_VaultClient]:
        """Gate reads during close and cap provider concurrency."""
        async with self._condition:
            if self._closing or self._closed:
                raise SecretProviderClosedError()
            self._active += 1
        try:
            async with self._semaphore:
                yield await self._get_client()
        finally:
            async with self._condition:
                self._active -= 1
                self._condition.notify_all()

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Fetch one current or pinned Azure Key Vault secret version."""
        if not isinstance(reference, SecretReference):
            raise TypeError("reference must be a SecretReference.")
        if _SECRET_NAME.fullmatch(reference.name) is None:
            raise ValueError("Azure secret names must contain only letters, digits, and hyphens.")
        if reference.version is not None and _VERSION.fullmatch(reference.version) is None:
            raise ValueError("Azure secret versions must be bounded provider version identifiers.")
        try:
            async with asyncio.timeout(self.config.request_timeout_seconds):
                async with self._use_client() as client:
                    response = await client.get_secret(reference.name, version=reference.version)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise SecretUnavailableError() from None
        except SecretError:
            raise
        except Exception as exc:
            raise _map_error(exc, pinned=reference.version is not None) from None
        return _decode_response(response)

    async def refresh(self, reference: SecretReference) -> SecretValue:
        """Read the current vault version again; no resolved values are cached."""
        return await self.resolve(reference)

    async def aclose(self) -> None:
        """Drain active requests and close the vault client followed by its credential."""
        async with self._close_lock:
            if self._closed:
                return
            async with self._condition:
                self._closing = True
                await self._condition.wait_for(lambda: self._active == 0)
            try:
                if self._client is not None:
                    result = self._client.close()
                    if inspect.isawaitable(result):
                        await result
                if self._credential is not None:
                    result = self._credential.close()
                    if inspect.isawaitable(result):
                        await result
            except asyncio.CancelledError:
                raise
            except Exception:
                raise SecretOperationError("client-close-failed") from None
            else:
                self._closed = True

    async def __aenter__(self) -> AzureSecretsProvider:
        """Return the provider for ``async with`` ownership."""
        if self._closing or self._closed:
            raise SecretProviderClosedError()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close client and credential on context exit."""
        await self.aclose()


def _default_credential_factory() -> _Credential:
    """Create Azure's asynchronous default credential chain on first resolution."""
    from azure.identity.aio import DefaultAzureCredential

    return cast(_Credential, DefaultAzureCredential())


def _default_client_factory(vault_url: str, credential: _Credential) -> _VaultClient:
    """Create the async Key Vault client using the caller-selected async identity."""
    from azure.keyvault.secrets.aio import SecretClient

    return cast(_VaultClient, SecretClient(vault_url=vault_url, credential=credential))


def _decode_response(response: Any) -> SecretValue:
    """Copy only the bounded secret text and immutable Key Vault version from the response."""
    try:
        value = response.value
        version = response.properties.version
        if not isinstance(value, str) or not isinstance(version, str):
            raise ValueError
        payload = value.encode("utf-8", errors="strict")
        if len(payload) > MAX_SECRET_BYTES:
            raise ValueError
        return SecretValue(payload, version)
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise SecretOperationError("invalid-provider-response") from None


def _map_error(exc: Exception, *, pinned: bool) -> Exception:
    """Map Azure status and exception category without exposing SDK messages or URLs."""
    status = getattr(exc, "status_code", None)
    name = exc.__class__.__name__
    if status == 404 or name == "ResourceNotFoundError":
        return SecretVersionNotFoundError() if pinned else SecretNotFoundError()
    if status in {401, 403} or name == "ClientAuthenticationError":
        return SecretAccessDeniedError()
    if (
        status in {408, 429}
        or (isinstance(status, int) and not isinstance(status, bool) and status >= 500)
        or name
        in {
            "ServiceRequestError",
            "ServiceResponseError",
        }
    ):
        return SecretUnavailableError()
    return SecretOperationError("provider-failure")


__all__ = ["AzureSecretsProvider"]
