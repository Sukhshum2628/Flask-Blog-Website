import os
import subprocess
import pytest
from app import app, mongo

# ---------------------------------------------------------------------------
# Database Isolation & Safety Verification Tests
# ---------------------------------------------------------------------------

def test_missing_test_mongo_uri_prevents_test_execution():
    """Verify that when TESTING=true, a missing TEST_MONGO_URI halts startup with RuntimeError."""
    cmd = [
        "python", "-c",
        "import os, unittest.mock; os.environ['TESTING'] = 'true'; os.environ.pop('TEST_MONGO_URI', None); unittest.mock.patch('dotenv.load_dotenv', lambda: None).start(); import app"
    ]
    env = os.environ.copy()
    env.pop('TEST_MONGO_URI', None)
    env['TESTING'] = 'true'

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "FATAL SECURITY ERROR: Automated testing requires an explicit TEST_MONGO_URI" in res.stderr

def test_production_database_name_rejected_for_testing():
    """Verify that TEST_MONGO_URI pointing to production database 'blogDB' halts startup."""
    cmd = [
        "python", "-c",
        "import os; os.environ['TESTING'] = 'true'; os.environ['TEST_MONGO_URI'] = 'mongodb://localhost:27017/blogDB'; import app"
    ]
    env = os.environ.copy()
    env['TESTING'] = 'true'
    env['TEST_MONGO_URI'] = 'mongodb://localhost:27017/blogDB'

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "Test database must be distinct from production" in res.stderr

def test_production_cluster_and_db_fingerprint_rejected():
    """Verify that TEST_MONGO_URI pointing to production cluster and blogDB halts startup."""
    cmd = [
        "python", "-c",
        "import os; os.environ['TESTING'] = 'true'; os.environ['TEST_MONGO_URI'] = 'mongodb+srv://user:pass@cluster0.e3az295.mongodb.net/blogDB?retryWrites=true&w=majority'; import app"
    ]
    env = os.environ.copy()
    env['TESTING'] = 'true'
    env['TEST_MONGO_URI'] = 'mongodb+srv://user:pass@cluster0.e3az295.mongodb.net/blogDB?retryWrites=true&w=majority'

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "Test database must be distinct from production" in res.stderr

def test_valid_isolated_test_database_accepted():
    """Verify that an explicit isolated test database is accepted in test mode."""
    cmd = [
        "python", "-c",
        "import os; from dotenv import load_dotenv; load_dotenv(); os.environ['TESTING'] = 'true'; import app; print('SUCCESS:', app.mongo.db.name)"
    ]
    env = os.environ.copy()
    env['TESTING'] = 'true'

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0
    assert "SUCCESS: blogDB_isolated_test" in res.stdout

def test_test_mode_never_falls_back_to_production_mongo_uri():
    """Verify that removing TEST_MONGO_URI while MONGO_URI is set fails fast rather than falling back."""
    cmd = [
        "python", "-c",
        "import os, unittest.mock; os.environ['TESTING'] = 'true'; os.environ.pop('TEST_MONGO_URI', None); unittest.mock.patch('dotenv.load_dotenv', lambda: None).start(); os.environ['MONGO_URI'] = 'mongodb://localhost:27017/blogDB'; import app"
    ]
    env = os.environ.copy()
    env['TESTING'] = 'true'
    env.pop('TEST_MONGO_URI', None)
    env['MONGO_URI'] = 'mongodb://localhost:27017/blogDB'

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "Automated testing requires an explicit TEST_MONGO_URI" in res.stderr

def test_active_test_database_is_not_production():
    """Assert that the currently running test suite's database is strictly not 'blogDB'."""
    assert mongo.db.name != "blogDB"
    assert "test" in mongo.db.name.lower()

def test_transaction_integration_runs_on_isolated_database():
    """Verify multi-document transactions work on the isolated test database."""
    client = mongo.cx
    with client.start_session() as session:
        with session.start_transaction():
            doc = mongo.db.test_isolation_probe.insert_one({"probe": "tx_isolation"}, session=session)
            assert doc.inserted_id is not None
            session.abort_transaction()

    # Confirmed rolled back on isolated test DB
    assert mongo.db.test_isolation_probe.find_one({"probe": "tx_isolation"}) is None

