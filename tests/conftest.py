"""
Pytest configuration and fixtures.
Sets up environment variables for testing before importing the app.
"""

import os
import pytest

# Set environment variables before any imports
os.environ["RED_KEY"] = "Drmhze8Qs0MJBu7tSXlZCEVDfn7xWrBfBNuwEkuLI48="
os.environ["BLUE_KEY"] = "Drmhze8Qs0MJBu7tSXlZCEVDfn7xWrBfBNuwEkuLI48="
os.environ["LLM_KEY"] = "Drmhze8Qs0MJBu7tSXlZCEVDfn7xWrBfBNuwEkuLI48="
os.environ["POSTGRES_HOST"] = "localhost"
os.environ["POSTGRES_PORT"] = "5432"
os.environ["POSTGRES_USER"] = "bayora"
os.environ["POSTGRES_PASSWORD"] = "bayora_password"
os.environ["POSTGRES_DB"] = "bayora_audit"
os.environ["KAFKA_BROKER"] = "localhost:9092"
os.environ["JWT_SECRET"] = "test_secret"
os.environ["AUDIT_SALT"] = "test_salt"
os.environ["AUDIT_SIGNING_KEY_B64"] = ""
os.environ["LLM_PROXY_PUBLIC_KEY_B64"] = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuP8JUR3ssVFzA5hnK01VFDwGckXZJ6ad8qhgPU3N50XIXdRcjnQzDU6EoyScJfqcLnHYKVrBvLdPf0fnYw8Nc9F5usK8k3eOF5EJIondPvZJ0dKMgLYBlYuyUh1ZQ4bgVUBC4Lh0EIZ7qTypfNFf7ZH0ECX24gwQU9PHLsE1znPTcepD4nTkxrFuM2FLmMBeumYhgsevWg6VrIugsCBY6qODJg+1jHY8KMqsBVkWF5//k2FlX366mI8FtcJPqlQDDv1M7mO3/GTB2n7KViy66pl02PUtB+mYzIp7cu0EO2FOirgZCFjZWB8gF9jT/aIb+YWZPRalYdeV0nErt8a76wIDAQAB"
os.environ["LLM_PROXY_PRIVATE_KEY_B64"] = "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC4/wlRHeyxUXMDmGcrTVUUPAZyRdknpp3yqGA9Tc3nRchd1FyOdDMNToSjJJwl+pwucdgpWsG8t09/R+djDw1z0Xm6wryTd44XkQkiid0+9knR0oyAtgGVi7JSHVlDhuBVQELguHQQhnupPKl80V/tkfQQJfbiDBBT08cuwTXOc9Nx6kPidOTGsW4zYUuYwF66ZiGCx69aDpWsi6CwIFjqo4MmD7WMdjwoyqwFWRYXn/+TYWVffrqYjwW1wk+qVAMO/UzuY7f8ZMHafspWLLrqmXTY9S0H6ZjMinty7QQ7YU6KuBkIWNlYHyAX2NP9ohv5hZk9FqVh15XScSu3xrvrAgMBAAECgf8Y+psLtsLyHUkMgAeQUT6rp283ZTcGtKNa07azf03wOS8hnmBYdWk8Fe8XKUlBk0hhQVNMhnSiZIRxCRnGPdMkPz45ExJSTpaUQrRW7QJQl6yCKFq/SqDbEHC2tshOPEXa+Li5sC5ADPmlk4LGk37PWXbWt1qnGfnnNZem9Dx6Vt0kiefLAKukEUKis/HAML4L+DlGbuoJJGFzeClvIb5+zdE7hU7Kae5EK22useBMu2yTUG4DJysbxQY/qQsDUIaKVMB97WTpPzXuTeUllbLuIvbiVZ6a4lwDBMBVYf2JV3uRnsOOSE95WN76Ve2UuB2kKnCo+NYf7/QBlXdnWfECgYEA9IQ+EDSdghUEie8giT03kjpDgt/RvC53nQTIrW5FqtosfxzUUFCJinUDrj64A9svhE84sCrc0i8pRJgzffXDVRq1rXCBKdv1NVZNTHEKNJyWJrEpJmKQTfd8+1Z12irj18XuD+c3ycM8OtgWUmGUvlhtCI439pMjHZz6t/A6jZECgYEAwa8yYxbyUVaMS+2g8F765uMKJtJuQKtLzYEgarbqZMp+FMy3BhsttU5QCnlvQ6ZIjzTRCDQFC0IccEE4OxF0QG7Mva+opQwinLolcyX2fY2wJsAfMU7q9bFrlTPpiHitNsCSP54xmqSBizRax1mKzEVl+OqFlyHYrPZ8Fg/+o7sCgYAlSJjSDcPKlvvXMHAsnPoBQQMUTJ6FbCxu89DJqRvUXmoUg8fX6z/drdP+2K9kXyKSsSW6rv52yhwnynFnjnbXXjg/lv0K7fAozt0Af+gHd6zpf2//212Xldon1Nophwqw1wxivmXiTPO9IT/eFeUBVShi+pSL84mSNWKBc47qEQKBgQCXOBI/C0tl9gzTu1RMV9vNKLZkWSd7lkI40PheWTHoP7DwzGSZf97QD7SueOFGEC3WoYYSwYqun49UlZcxhw8cv2VbNCqXskHT3AIhRSKOJHHDz3yLIvKPoVY9x6otwwp6FSAaS4ivFIGQDfBSdLbJheV30qM6vFJPuKJpF1PYwQKBgHPcPjhag5ECcRrDu+sAjQji/W8oF7mNKQ3s6osztUUBid5MSOmCTigoI98C59JONausRW34ahCMu6F5ilb/lu19TVfqgSSlchUoyXf2nzcY8F3FZLI59oYyltNeTqxLgHYhvKZcWZLJSNGMt4gmNp3GCf2pUVipTC7s19ysmuM+"
os.environ["GOOGLE_API_KEY"] = "test_key"
os.environ["MOCK_LLM"] = "1"


@pytest.fixture(scope="session", autouse=True)
def initialize_crypto_keys():
    """Initialize RSA keys in bus module for testing."""
    from bayora.services.session_manager import bus
    bus.load_llm_proxy_public_key()
