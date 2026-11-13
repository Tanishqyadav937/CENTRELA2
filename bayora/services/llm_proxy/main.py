import os
import asyncio
import logging
import base64
from dotenv import load_dotenv
load_dotenv() # Load from .env file

from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from bayora.services.llm_proxy.inference import SandboxedInference
from bayora.services.llm_proxy.bus import LLMProxyBus
from contextlib import asynccontextmanager
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
inference_engine = SandboxedInference()
proxy_bus = LLMProxyBus(inference_engine)

consumer_task = None
producer = None

# LLM Proxy private key for session key unwrapping (will be loaded in lifespan)
LLM_PROXY_PRIVATE_KEY = None

def load_llm_proxy_private_key():
    """Load the LLM Proxy private key from environment."""
    global LLM_PROXY_PRIVATE_KEY
    
    llm_proxy_priv_b64 = os.getenv("LLM_PROXY_PRIVATE_KEY_B64")
    if not llm_proxy_priv_b64:
        raise RuntimeError("Missing required environment variable: LLM_PROXY_PRIVATE_KEY_B64")
    
    try:
        priv_key_der = base64.b64decode(llm_proxy_priv_b64)
        private_key = serialization.load_der_private_key(priv_key_der, password=None, backend=default_backend())
        logger.info("✅ Loaded LLM Proxy private key for session key unwrapping")
        LLM_PROXY_PRIVATE_KEY = private_key
        return private_key
    except Exception as e:
        raise RuntimeError(f"Failed to load LLM Proxy private key: {e}")

async def consume_llm_requests():
    consumer = AIOKafkaConsumer(
        "llm.requests",
        bootstrap_servers=KAFKA_BROKER,
        group_id="llm_proxy_group"
    )
    await consumer.start()
    logger.info("🚀 LLM Proxy listening on Kafka topic 'llm.requests'...")
    try:
        async for msg in consumer:
            headers = dict(msg.headers) if msg.headers else {}
            session_id = headers.get("session_id", b"").decode()
            wrapped_session_key_b64 = headers.get("wrapped_session_key", b"").decode()
            encrypted_payload = msg.value

            # Validate session_id
            if not session_id:
                logger.error("❌ Missing session_id in Kafka headers")
                continue
            
            # Validate and unwrap session key
            if not wrapped_session_key_b64:
                logger.error(f"❌ Missing wrapped_session_key header for session {session_id}")
                continue
            
            try:
                # Unwrap the session key using RSA-OAEP
                wrapped_key_bytes = base64.b64decode(wrapped_session_key_b64)
                session_key_bytes = LLM_PROXY_PRIVATE_KEY.decrypt(
                    wrapped_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                session_key = session_key_bytes.decode()
            except Exception as e:
                logger.error(f"❌ Failed to unwrap session key for session {session_id}: {e}")
                continue
            
            try:
                encrypted_resp = proxy_bus.process_request(encrypted_payload, session_key)
                if producer:
                    await producer.send_and_wait(
                        "llm.responses", 
                        encrypted_resp,
                        headers=[("session_id", session_id.encode())]
                    )
                logger.info(f"✅ Processed request for session {session_id}")
            except Exception as e:
                logger.error(f"❌ Error processing message for session {session_id}: {e}")
    finally:
        await consumer.stop()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global producer, consumer_task, LLM_PROXY_PRIVATE_KEY
    
    # Startup: validate required keys
    required_keys = ["LLM_KEY", "JWT_SECRET", "LLM_PROXY_PRIVATE_KEY_B64"]
    missing_keys = [key for key in required_keys if not os.getenv(key)]
    if missing_keys:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_keys)}")
    
    # Load the private key
    try:
        load_llm_proxy_private_key()
    except RuntimeError as e:
        logger.error(f"❌ {e}")
        raise
    
    logger.info("✅ All required keys configured")
    
    try:
        producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BROKER)
        await producer.start()
        consumer_task = asyncio.create_task(consume_llm_requests())
    except Exception as e:
        logger.warning(f"⚠️ Could not connect to Kafka: {e}. Running in HTTP mock mode only.")
        
    yield
    
    if producer:
        await producer.stop()
    if consumer_task:
        consumer_task.cancel()

app = FastAPI(lifespan=lifespan)

# HTTP Fallback/Mock endpoints are kept for the original integration_demo.py fallback
from pydantic import BaseModel
class LLMRequest(BaseModel):
    session_id: str
    session_key: str
    encrypted_prompt: str

@app.post("/llm/infer")
def infer(req: LLMRequest):
    try:
        encrypted_response = proxy_bus.process_request(
            req.encrypted_prompt.encode(), 
            req.session_key
        )
        return {"encrypted_response": encrypted_response.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/llm/session/end")
def end_session():
    proxy_bus.handle_session_end()
    return {"status": "memory_cleared"}
