#!/usr/bin/env python3
"""
Generate RSA-2048 keypair for LLM Proxy session key wrapping.
Output is base64-encoded for use in .env files.

Usage:
  python3 bayora/infra/scripts/generate-llm-proxy-keys.py
"""

import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_llm_proxy_keys():
    """Generate RSA-2048 keypair for LLM Proxy session key wrapping."""
    
    # Generate 2048-bit RSA keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize to DER format (binary)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Encode to base64
    private_b64 = base64.b64encode(private_der).decode()
    public_b64 = base64.b64encode(public_der).decode()
    
    return private_b64, public_b64

if __name__ == "__main__":
    private_b64, public_b64 = generate_llm_proxy_keys()
    
    print("=" * 80)
    print("LLM Proxy RSA-2048 Keypair Generation")
    print("=" * 80)
    print()
    print("Add the following to your .env file:")
    print()
    print(f"LLM_PROXY_PRIVATE_KEY_B64={private_b64}")
    print()
    print(f"LLM_PROXY_PUBLIC_KEY_B64={public_b64}")
    print()
    print("=" * 80)
