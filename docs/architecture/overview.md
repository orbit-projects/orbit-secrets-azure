# Architecture

This adapter maps Azure Key Vault reads to the shared `orbit-secrets` contract. It owns only provider-specific SDK/client construction, resource-name validation, identity, response parsing, error classification, finite request settings, and cleanup. It does not own a cache or rotation schedule.

## Version mapping

SecretReference.name is a Key Vault secret name; an explicit version is an immutable Key Vault version. Key Vault text is returned as UTF-8 bytes with its exact version.

`refresh()` performs a new SDK read. The provider SDK may internally retry transient transport failures according to its bounded policy; Orbit does not add a second retry loop. Each successful response is checked for a bounded payload and a non-empty version before constructing `SecretValue`.

## Failure mapping

Not-found and version-not-found outcomes are separate; authorization failures use a stable access-denied type; throttling, deadlines, and transport unavailability are marked retryable. Unknown SDK exceptions become a generic provider failure. Exception text and response bodies are not chained or exposed.

## Resource ownership

Client construction is lazy. Concurrent calls are bounded. Shutdown prevents new work, waits for active operations to drain, then closes every owned SDK resource. If cleanup fails, a sanitized error is raised and the provider remains closed to new work so callers cannot reuse a partially closed client.
