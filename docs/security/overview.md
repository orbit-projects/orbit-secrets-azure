# Security

The adapter reads secrets only; it does not create, rotate, update, or delete provider secrets. Provider credentials are resolved through DefaultAzureCredential async chain, preferably managed identity. Grant read permission only for the specific secret resources and versions required.

Secret bytes and version metadata never appear in repr or Orbit errors. Provider SDK exceptions and response bodies are not included in exception chains. The secret resource name is still operational metadata and must not be logged casually. TLS verification remains enabled through the provider SDK.

Do not rely on the adapter to redact caller log messages or erase copied plaintext. Python cannot guarantee zeroization. Use short-lived values and rotate dependent clients safely. Never fall back to static credentials or a different provider after failure.
