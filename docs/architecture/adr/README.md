# Architecture decisions

This adapter follows the provider-neutral secret resolution and versioning contract in
[`orbit-secrets`](https://github.com/orbit-projects/orbit-secrets). Provider-specific semantics
and limitations are documented in [the architecture overview](../overview.md).

A new ADR is required before adding caching, write operations, rotation orchestration, or a new
identity fallback because each changes the security and lifecycle boundary.
