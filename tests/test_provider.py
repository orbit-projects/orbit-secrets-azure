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
"""Azure Key Vault adapter version, identity cleanup, and error behavior."""

import pytest
from orbit_secrets import SecretAccessDeniedError, SecretReference

from orbit_secrets_azure import AzureSecretsConfig, AzureSecretsProvider


class Properties:
    version = "abc-123"


class Response:
    value = "azure-secret"
    properties = Properties()


class FakeCredential:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response or Response()
        self.error = error
        self.args = None
        self.closed = False

    async def get_secret(self, name, version=None):
        self.args = (name, version)
        if self.error:
            raise self.error
        return self.response

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_resolve_returns_version_and_closes_client_and_identity():
    credential, client = FakeCredential(), FakeClient()
    provider = AzureSecretsProvider(
        AzureSecretsConfig(vault_url="https://vault.example.net"),
        credential_factory=lambda: credential,
        client_factory=lambda _url, _credential: client,
    )
    result = await provider.resolve(SecretReference(name="orders-db", version="pinned"))
    assert result.reveal_text() == "azure-secret"
    assert result.version == "abc-123"
    assert client.args == ("orders-db", "pinned")
    await provider.aclose()
    assert client.closed and credential.closed


@pytest.mark.asyncio
async def test_denied_response_is_sanitized():
    class HttpResponseError(Exception):
        status_code = 403

    client = FakeClient(error=HttpResponseError("secret token"))
    provider = AzureSecretsProvider(
        AzureSecretsConfig(vault_url="https://vault.example.net"),
        credential_factory=FakeCredential,
        client_factory=lambda _url, _credential: client,
    )
    with pytest.raises(SecretAccessDeniedError) as caught:
        await provider.resolve(SecretReference(name="orders-db"))
    assert "secret token" not in str(caught.value)
    await provider.aclose()


@pytest.mark.parametrize(
    "url",
    [
        "http://vault.example.net",
        "https://user:pass@vault.example.net",
        "https://vault.example.net/?x=1",
    ],
)
def test_config_rejects_unsafe_vault_urls(url: str) -> None:
    with pytest.raises(ValueError):
        AzureSecretsConfig(vault_url=url)
