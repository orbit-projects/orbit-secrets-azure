# Operations

Configure the minimal required scope and prefer DefaultAzureCredential async chain, preferably managed identity. The adapter uses default provider identity behavior; it does not create identities or permissions. `resolve()` reads current or pinned version; `refresh()` performs a fresh provider read. Values are not cached.

Set request timeouts and concurrency to match the downstream service's quotas and the application's shutdown budget. Keep retry layers bounded: SDK retries plus application retries can multiply latency and request volume. Cancellation is propagated promptly.

Install the adapter during application composition and call `aclose()` during shutdown. Monitor sanitized error codes and latency without recording secret names, version IDs, payloads, credentials, or SDK exception messages.

Fake-client tests cover contract and lifecycle behavior. Live account validation, identity permissions, throttling, rotation, and service-specific quotas remain external release gates.
