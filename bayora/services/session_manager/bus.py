import os
import base64
import json
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_key(env_var):
    key = os.getenv(env_var)
    if not key:
        return Fernet.generate_key()
    return key.encode()

RED_KEY = get_key("RED_KEY")
BLUE_KEY = get_key("BLUE_KEY")
LLM_KEY = get_key("LLM_KEY")

# Load LLM Proxy public key for session key wrapping (will be loaded in lifespan)
LLM_PROXY_PUBLIC_KEY = None

def load_llm_proxy_public_key():
    """Load the LLM Proxy public key from environment."""
    global LLM_PROXY_PUBLIC_KEY
    
    llm_proxy_pub_b64 = os.getenv("LLM_PROXY_PUBLIC_KEY_B64")
    if not llm_proxy_pub_b64:
        raise RuntimeError("Missing required environment variable: LLM_PROXY_PUBLIC_KEY_B64")
    
    try:
        pub_key_der = base64.b64decode(llm_proxy_pub_b64)
        public_key = serialization.load_der_public_key(pub_key_der, backend=default_backend())
        logger.info("✅ Loaded LLM Proxy public key for session key wrapping")
        LLM_PROXY_PUBLIC_KEY = public_key
        return public_key
    except Exception as e:
        raise RuntimeError(f"Failed to load LLM Proxy public key: {e}")

class IsolatedMessageBus:
    def __init__(self, audit_log, kafka_producer=None, batch_size=5):
        self.audit_log = audit_log
        self.red_fernet = Fernet(RED_KEY)
        self.blue_fernet = Fernet(BLUE_KEY)
        self.llm_fernet = Fernet(LLM_KEY)
        self.kafka_producer = kafka_producer
        self.batch_size = batch_size
        
        self.session_stores = {} # session_id -> list of encrypted responses
        self.unreleased_stores = {} # session_id -> list of unreleased encrypted responses
        self.session_keys = {}   # session_id -> Fernet instance
        self.session_raw_keys = {} # session_id -> raw bytes string

    async def produce(self, topic: str, message: bytes, headers=None):
        if self.kafka_producer and hasattr(self.kafka_producer, "send_and_wait"):
            await self.kafka_producer.send_and_wait(topic, message, headers=headers)
        elif isinstance(self.kafka_producer, dict):
            # Mock behavior for testing
            if topic not in self.kafka_producer:
                self.kafka_producer[topic] = []
            self.kafka_producer[topic].append(message)
            print(f"[MOCK KAFKA] Produced to {topic}: {message[:20]}...")
        else:
            print(f"[MOCK KAFKA] Produced to {topic}: {message[:20]}...")

    async def consume_red_prompt(self, session_id: str, encrypted_payload: bytes, session_key_str: str):
        # 1. Decrypt with RED_KEY
        try:
            plaintext = self.red_fernet.decrypt(encrypted_payload)
        except Exception as e:
            raise ValueError("Failed to decrypt red prompt")

        # 2. Re-encrypt with LLM_KEY
        llm_encrypted = self.llm_fernet.encrypt(plaintext)

        # 3. Wrap the session key with LLM Proxy's public key using RSA-OAEP
        try:
            session_key_bytes = session_key_str.encode() if isinstance(session_key_str, str) else session_key_str
            wrapped_session_key = LLM_PROXY_PUBLIC_KEY.encrypt(
                session_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            wrapped_session_key_b64 = base64.b64encode(wrapped_session_key).decode()
        except Exception as e:
            logger.error(f"❌ Failed to wrap session key: {e}")
            raise

        # 4. Publish to llm.requests (wrapped_session_key in headers, NO plaintext session_key)
        headers = [
            ("session_id", session_id.encode()),
            ("wrapped_session_key", wrapped_session_key_b64.encode()),
        ]
        await self.produce("llm.requests", llm_encrypted, headers=headers)
        
        # 5. Audit Log
        self.audit_log.append("PROMPT_SENT", "red-team", session_id, plaintext)

    async def handle_llm_response(self, session_id: str, encrypted_response: bytes):
        # 1. Decrypt with SESSION_KEY
        session_fernet = self.session_keys.get(session_id)
        if not session_fernet:
            # Gracefully ignore responses for ended or non-existent sessions
            print(f"[Session Manager] Info: Received response for ended/invalid session {session_id}. Ignoring.")
            return
            
        try:
            plaintext = session_fernet.decrypt(encrypted_response)
        except Exception:
            raise ValueError("Failed to decrypt LLM response")
            
        # 2. Store encrypted response in session store (encrypted with SESSION_KEY)
        if session_id not in self.session_stores:
            self.session_stores[session_id] = []
            self.unreleased_stores[session_id] = []
        
        self.session_stores[session_id].append(encrypted_response)
        self.unreleased_stores[session_id].append(encrypted_response)
        
        # 3. Audit Log
        self.audit_log.append("RESPONSE_RECEIVED", "llm-sandbox", session_id, plaintext)

        # 4. Check for batch release
        if len(self.unreleased_stores[session_id]) >= self.batch_size:
            await self.release_unreleased_batch(session_id)

    async def release_unreleased_batch(self, session_id: str):
        if session_id not in self.unreleased_stores or not self.unreleased_stores[session_id]:
            return
            
        session_fernet = self.session_keys[session_id]
        batch_plaintext = []
        
        # Decrypt the current unreleased batch
        for encrypted_resp in self.unreleased_stores[session_id]:
            batch_plaintext.append(session_fernet.decrypt(encrypted_resp).decode('utf-8'))
            
        # Re-encrypt bundle with BLUE_KEY
        bundle_json = json.dumps(batch_plaintext)
        bundle_bytes = bundle_json.encode('utf-8')
        blue_encrypted = self.blue_fernet.encrypt(bundle_bytes)
        
        # Produce to blue.evaluation
        headers = [("session_id", session_id.encode())]
        await self.produce("blue.evaluation", blue_encrypted, headers=headers)

        # Audit Log
        self.audit_log.append("BATCH_RELEASED", "session-manager", session_id, bundle_bytes)

        # Clear unreleased store for this session
        self.unreleased_stores[session_id] = []

    async def release_batch_to_blue(self, session_id: str):
        # Flush any remaining unreleased responses
        await self.release_unreleased_batch(session_id)
