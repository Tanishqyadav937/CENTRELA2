import os
import asyncio
import json
import logging
from dotenv import load_dotenv
load_dotenv() # Load from .env file

import hashlib
import time
import psycopg2
from psycopg2.extras import RealDictCursor
import threading
from fastapi import FastAPI
from aiokafka import AIOKafkaConsumer
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")

class TamperEvidentLedger:
    def __init__(self):
        self.db_host = os.getenv("POSTGRES_HOST", "localhost")
        self.db_port = os.getenv("POSTGRES_PORT", "5432")
        self.db_user = os.getenv("POSTGRES_USER", "bayora")
        self.db_pass = os.getenv("POSTGRES_PASSWORD", "bayora_password")
        self.db_name = os.getenv("POSTGRES_DB", "bayora_audit")
        
        self.conn = None
        self.lock = threading.Lock()
        self._head_hash = hashlib.sha256(b"genesis").hexdigest()
        self.chain = [] # fallback memory chain
        
        self._init_db()

    def _init_db(self):
        try:
            self.conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_pass,
                dbname=self.db_name
            )
            self.conn.autocommit = False  # Use explicit transactions
            
            with self.conn:
                with self.conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS audit_entries (
                            id SERIAL PRIMARY KEY,
                            event_type VARCHAR(255) NOT NULL,
                            source_namespace VARCHAR(255) NOT NULL,
                            session_id VARCHAR(255) NOT NULL,
                            payload_hash VARCHAR(64) NOT NULL,
                            timestamp_ns BIGINT NOT NULL,
                            prev_hash VARCHAR(64) NOT NULL,
                            entry_hash VARCHAR(64) NOT NULL UNIQUE
                        );
                    """)
                    cur.execute("SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1;")
                    row = cur.fetchone()
                    if row:
                        self._head_hash = row[0]
                        logger.info(f"✅ Audit Service recovered from DB. Head hash: {self._head_hash[:8]}...")
        except Exception as e:
            logger.warning(f"⚠️ Could not connect to PostgreSQL: {e}. Falling back to in-memory mode.")
            self.conn = None

    def _reconnect_db(self):
        """Attempt to reconnect to PostgreSQL."""
        try:
            if self.conn:
                try:
                    self.conn.close()
                except:
                    pass
            
            self.conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_pass,
                dbname=self.db_name
            )
            self.conn.autocommit = False
            logger.info("✅ Reconnected to PostgreSQL")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to reconnect to PostgreSQL: {e}")
            self.conn = None
            return False

    def append(self, event_type: str, source_ns: str, session_id: str, payload_hash: str):
        # Note: We receive the hash from session-manager, not the raw payload
        timestamp_ns = time.time_ns()
        
        with self.lock:
            entry = {
                "event_type": event_type,
                "source_namespace": source_ns,
                "session_id": session_id,
                "payload_hash": payload_hash,
                "timestamp_ns": timestamp_ns,
                "prev_hash": self._head_hash
            }
            
            entry_str = json.dumps(entry, sort_keys=True).encode("utf-8")
            entry_hash = hashlib.sha256(entry_str).hexdigest()
            entry["entry_hash"] = entry_hash
            
            if self.conn:
                try:
                    # Use context manager for automatic transaction management
                    # Commit on success, rollback on exception
                    with self.conn:
                        with self.conn.cursor() as cur:
                            # Idempotent INSERT: ON CONFLICT DO NOTHING to handle duplicates
                            cur.execute("""
                                INSERT INTO audit_entries 
                                (event_type, source_namespace, session_id, payload_hash, timestamp_ns, prev_hash, entry_hash)
                                VALUES (%(event_type)s, %(source_namespace)s, %(session_id)s, %(payload_hash)s, %(timestamp_ns)s, %(prev_hash)s, %(entry_hash)s)
                                ON CONFLICT (entry_hash) DO NOTHING
                            """, entry)
                    # Only update _head_hash AFTER successful transaction commit
                    self._head_hash = entry_hash
                    logger.info(f"✅ Audit entry committed: {entry_hash[:8]}...")
                    return entry
                except Exception as e:
                    # On failure: log, do NOT advance _head_hash, return None
                    # Caller (Kafka consumer) should retry or send to DLQ
                    logger.error(f"❌ Failed to persist audit log entry: {e}")
                    return None
            else:
                # Fallback to in-memory chain
                self.chain.append(entry)
                self._head_hash = entry_hash
                return entry

    def verify(self):
        current_prev = hashlib.sha256(b"genesis").hexdigest()
        chain_length = 0
        
        with self.lock:
            if self.conn:
                try:
                    with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("SELECT * FROM audit_entries ORDER BY id ASC;")
                        for row in cur:
                            entry = {
                                "event_type": row["event_type"],
                                "source_namespace": row["source_namespace"],
                                "session_id": row["session_id"],
                                "payload_hash": row["payload_hash"],
                                "timestamp_ns": row["timestamp_ns"],
                                "prev_hash": row["prev_hash"]
                            }
                            if entry["prev_hash"] != current_prev:
                                return False, chain_length, current_prev
                                
                            entry_str = json.dumps(entry, sort_keys=True).encode("utf-8")
                            recomputed_hash = hashlib.sha256(entry_str).hexdigest()
                            
                            if recomputed_hash != row["entry_hash"]:
                                return False, chain_length, current_prev
                                
                            current_prev = recomputed_hash
                            chain_length += 1
                            
                    return True, chain_length, current_prev
                except Exception as e:
                    logger.error(f"❌ Database error during verify: {e}")
                    return False, 0, current_prev
            else:
                for entry in self.chain:
                    if entry["prev_hash"] != current_prev:
                        return False, chain_length, current_prev
                    
                    entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
                    entry_str = json.dumps(entry_copy, sort_keys=True).encode("utf-8")
                    recomputed_hash = hashlib.sha256(entry_str).hexdigest()
                    
                    if recomputed_hash != entry["entry_hash"]:
                        return False, chain_length, current_prev
                        
                    current_prev = recomputed_hash
                    chain_length += 1
                    
                return True, chain_length, current_prev

ledger = TamperEvidentLedger()

async def consume_audit_events():
    consumer = AIOKafkaConsumer(
        "audit.events",
        bootstrap_servers=KAFKA_BROKER,
        group_id="audit_service_group",
        enable_auto_commit=False  # Manual commit control
    )
    # Producer for DLQ
    producer = None
    try:
        from aiokafka import AIOKafkaProducer
        producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BROKER)
        await producer.start()
    except Exception as e:
        logger.error(f"Could not initialize DLQ producer: {e}")
    
    await consumer.start()
    logger.info("✅ Audit Service listening to audit.events...")
    
    try:
        async for msg in consumer:
            event = None
            try:
                event = json.loads(msg.value.decode())
                
                # Retry logic: up to 3 attempts with backoff
                max_retries = 3
                for attempt in range(max_retries):
                    # Attempt to reconnect DB before each retry if not connected
                    if not ledger.conn and attempt > 0:
                        ledger._reconnect_db()
                    
                    result = ledger.append(
                        event["event_type"],
                        event["source_namespace"],
                        event["session_id"],
                        event["payload_hash"]
                    )
                    
                    if result is not None:
                        # Success: ack the message
                        await consumer.commit()
                        logger.info(f"[Audit Service] Logged {event['event_type']} for {event['session_id']}")
                        break
                    else:
                        # Failure: log and retry
                        if attempt < max_retries - 1:
                            # Short backoff before retry (using asyncio.sleep)
                            backoff_ms = (2 ** attempt) * 100  # 100ms, 200ms, 400ms
                            await asyncio.sleep(backoff_ms / 1000.0)
                            logger.warning(f"[Audit Service] Retry attempt {attempt + 1}/{max_retries} for {event['session_id']}")
                        else:
                            # All retries exhausted: send to DLQ
                            logger.error(f"[Audit Service] All {max_retries} retries exhausted for {event['session_id']}. Sending to DLQ.")
                            if producer:
                                try:
                                    await producer.send_and_wait(
                                        "audit.events.dlq",
                                        msg.value
                                    )
                                    logger.info(f"[Audit Service] Message sent to DLQ for {event['session_id']}")
                                    # Commit the offset ONLY after successful DLQ send
                                    await consumer.commit()
                                    logger.info(f"[Audit Service] Offset committed after DLQ send")
                                except Exception as dlq_error:
                                    logger.error(f"[Audit Service] Failed to send to DLQ: {dlq_error}")
                                    # Do NOT commit if DLQ send fails; message will be retried
                            else:
                                # No producer available; still commit to avoid infinite loop
                                logger.error(f"[Audit Service] No DLQ producer available; committing offset")
                                await consumer.commit()
                
            except Exception as e:
                logger.error(f"[Audit Service] Error processing event: {e}")
                # Do NOT ack on parsing error; will be retried
                
    finally:
        if producer:
            await producer.stop()
        await consumer.stop()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: validate required keys
    required_keys = ["AUDIT_SALT", "AUDIT_SIGNING_KEY_B64", "JWT_SECRET"]
    missing_keys = [key for key in required_keys if not os.getenv(key)]
    if missing_keys:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_keys)}")
    logger.info("✅ All required keys configured")
    
    asyncio.create_task(consume_audit_events())
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/verify")
async def verify_audit():
    valid, length, head = ledger.verify()
    return {"valid": valid, "chain_length": length, "head_hash": head}
