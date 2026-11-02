import os
import subprocess
import time
import pytest
from pymongo import MongoClient

# Path to local mongod binary
MONGOD_PATH = r"C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe"
TEST_PORT = "27018"
TEST_REPLSET = "rsTest"
TEST_DB_NAME = "blogDB_isolated_test"

_mongod_process = None

def pytest_configure(config):
    """Start local ephemeral replica set before tests run if not already running."""
    global _mongod_process

    # Check if 127.0.0.1:27018 is already up and primary
    try:
        c = MongoClient(f"mongodb://127.0.0.1:{TEST_PORT}/?directConnection=true", serverSelectionTimeoutMS=500)
        c.admin.command("ping")
        # Already running
        return
    except Exception:
        pass

    # Start ephemeral mongod replica set
    tmp_dir = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "mongo_test_rs")
    os.makedirs(tmp_dir, exist_ok=True)

    cmd = [
        MONGOD_PATH,
        "--dbpath", tmp_dir,
        "--port", TEST_PORT,
        "--replSet", TEST_REPLSET,
        "--bind_ip", "127.0.0.1"
    ]
    _mongod_process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Wait for mongod to accept connections
    time.sleep(2)
    c = MongoClient(f"mongodb://127.0.0.1:{TEST_PORT}/?directConnection=true", serverSelectionTimeoutMS=3000)
    try:
        c.admin.command("replSetInitiate", {
            "_id": TEST_REPLSET,
            "members": [{"_id": 0, "host": f"127.0.0.1:{TEST_PORT}"}]
        })
    except Exception:
        pass  # already initiated

    # Ensure primary status before tests begin
    for _ in range(20):
        try:
            status = c.admin.command("hello")
            if status.get("isWritablePrimary"):
                break
        except Exception:
            pass
        time.sleep(0.5)

    # Seed required persona user (alice_dev) for CSRF and session tests
    try:
        from werkzeug.security import generate_password_hash
        test_db = c[TEST_DB_NAME]
        test_db.users.update_one(
            {"username": "alice_dev"},
            {"$set": {
                "username": "alice_dev",
                "email": "alice@example.com",
                "password": generate_password_hash("Password123!", method="scrypt"),
                "token_version": 1,
                "bio": "Full-stack developer loving Python and React.",
                "avatar_url": "https://ui-avatars.com/api/?name=Alice+Dev",
                "bookmarks": []
            }},
            upsert=True
        )
    except Exception as e:
        print(f"Warning: could not seed alice_dev into test db: {e}")

def pytest_unconfigure(config):
    """Clean up spawned local mongod process when test session ends."""
    global _mongod_process
    if _mongod_process is not None:
        try:
            _mongod_process.terminate()
            _mongod_process.wait(timeout=5)
        except Exception:
            try:
                _mongod_process.kill()
            except Exception:
                pass
        _mongod_process = None

