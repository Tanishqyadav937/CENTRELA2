# Environment Configuration

This document describes all environment variables required for Centinela deployment.

## Encryption Keys

### Symmetric Encryption (Fernet)

Generate symmetric keys:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

- **RED_KEY**: Encryption key for Red Team prompts
- **BLUE_KEY**: Encryption key for Blue Team responses
- **LLM_KEY**: Encryption key for LLM Proxy requests

### Asymmetric Encryption (RSA-OAEP for Session Key Wrapping)

Generate RSA keypair for LLM Proxy session key wrapping:
```bash
python3 bayora/infra/scripts/generate-llm-proxy-keys.py
```

This will output `LLM_PROXY_PUBLIC_KEY_B64` and `LLM_PROXY_PRIVATE_KEY_B64` in base64 format.

- **LLM_PROXY_PUBLIC_KEY_B64**: Base64-encoded RSA-2048 public key (used by Session Manager to wrap session keys)
- **LLM_PROXY_PRIVATE_KEY_B64**: Base64-encoded RSA-2048 private key (used by LLM Proxy to unwrap session keys)

## Database Configuration

- **POSTGRES_HOST**: PostgreSQL host (default: `localhost`)
- **POSTGRES_PORT**: PostgreSQL port (default: `5432`)
- **POSTGRES_USER**: PostgreSQL user (default: `bayora`)
- **POSTGRES_PASSWORD**: PostgreSQL password (default: `bayora_password`)
- **POSTGRES_DB**: PostgreSQL database name (default: `bayora_audit`)

## Kafka Configuration

- **KAFKA_BROKER**: Kafka bootstrap server (default: `localhost:9092`)

## Authentication & Authorization

- **JWT_SECRET**: Secret key for JWT token signing and validation

## Audit Service Configuration

- **AUDIT_SALT**: Salt for HMAC-SHA256 payload hashing (change from default for production)
- **AUDIT_SIGNING_KEY_B64**: Base64-encoded Ed25519 private key for signing audit entries

## LLM Configuration

- **GOOGLE_API_KEY**: API key for Google Generative AI (if using Google models)
- **MOCK_LLM**: Set to `1` to use mock LLM responses (default: `0`)
- **OLLAMA_HOST**: Ollama host URL (default: `http://host.docker.internal:11434`)
- **OLLAMA_MODEL**: Ollama model name (default: `llama3`)

## Key Generation

### Symmetric Keys
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### RSA Keypair (2048-bit)
```bash
python3 bayora/infra/scripts/generate-llm-proxy-keys.py
```

### Ed25519 Signing Key (Audit Service)
```bash
python3 -c "
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64
private_key = ed25519.Ed25519PrivateKey.generate()
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
print('AUDIT_SIGNING_KEY_B64=' + base64.b64encode(private_pem).decode())
"
```

## Security Best Practices

1. **Never commit `.env` files to version control**
2. **Rotate keys periodically** for production deployments
3. **Use different keys for different environments** (dev, staging, prod)
4. **Store secrets in a secure vault** (AWS Secrets Manager, HashiCorp Vault, etc.)
5. **Use strong, randomly-generated secrets** (minimum 32 bytes of entropy)

## Example .env File

See `.env.example` for a template. Copy and customize:
```bash
cp .env.example .env
# Edit .env with your values
```
