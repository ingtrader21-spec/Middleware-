# Security

- Bind only to the internal Docker network; publish no host ports or console.
- Require native storage TLS using externally mounted certificate material.
- Keep root credentials in mounted secret files and use them only for bootstrap.
- Assign one least-privilege policy per middleware/worker identity.
- Never issue a storage identity to Server B.
- Production is blocked until an external KMS provider is selected and tested.
