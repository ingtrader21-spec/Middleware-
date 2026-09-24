# AI orchestration architecture

All callers submit versioned commands to Middleware. PostgreSQL is the durable authority. The Qwen worker initiates outbound mTLS/HMAC requests, claims fenced leases, calls only loopback model runtimes, and returns bounded results.

```text
Browser / Odoo mock / VICIdial synthetic / inactive n8n
                         |
                         v
                Middleware AI Router
                         |
                         v
                PostgreSQL AI jobs
                         ^
                         | outbound HTTPS mTLS + HMAC
                    Qwen worker
                     /       \
          127.0.0.1:4000   127.0.0.1:11434
              LiteLLM          Ollama
```

Server A never connects to a Server B runtime. LiteLLM and Ollama are not network services for other Codestra servers.
