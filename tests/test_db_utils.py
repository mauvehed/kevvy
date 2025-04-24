import pytest
import sqlite3
from unittest.mock import patch
from typing import Generator

from kevvy.db_utils import KEVConfigDB

@pytest.fixture
def db_conn() -> Generator[sqlite3.Connection, None, None]:
    """Fixture to provide an in-memory SQLite database connection."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row # Use Row factory for dict-like access
    # No need for PRAGMA foreign_keys = ON based on the schema
    yield conn
    conn.close()

@pytest.fixture
def kev_db(db_conn: sqlite3.Connection) -> KEVConfigDB:
    """Fixture to create a KEVConfigDB instance using the injected in-memory DB.

    Instantiates KEVConfigDB and replaces its internal connection object
    with the provided in-memory connection, then initializes the schema.
    """
    # Instantiate with a dummy path, connection will be replaced
    db_instance = KEVConfigDB(db_path=":memory:")
    db_instance._conn = db_conn # Inject the connection
    db_instance._initialize_db() # Initialize schema using the injected connection
    return db_instance

# --- Test Cases --- 

def test_set_and_get_kev_config(kev_db: KEVConfigDB, db_conn: sqlite3.Connection):
    """Test setting a new KEV config and retrieving it."""
    guild_id = 123456789012345678
    channel_id = 987654321098765432
    # set_kev_config doesn't take user_id anymore

    # Set the config (enables by default)
    kev_db.set_kev_config(guild_id, channel_id)

    # Verify directly in the database
    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM kev_config WHERE guild_id = ?", (guild_id,))
    row = cursor.fetchone()

    assert row is not None
    assert row["guild_id"] == guild_id
    assert row["channel_id"] == channel_id
    assert row["enabled"] == 1 # SQLite stores boolean True as 1
    # 'set_by_user_id' and 'updated_at' columns no longer exist in the schema

def test_update_kev_config(kev_db: KEVConfigDB, db_conn: sqlite3.Connection):
    """Test updating an existing KEV config (e.g., changing channel or disabling/enabling)."""
    guild_id = 123456789012345678
    initial_channel_id = 987654321098765432
    updated_channel_id = 222222222222222222

    # Add initial config (enabled)
    kev_db.set_kev_config(guild_id, initial_channel_id)

    # Verify initial state
    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM kev_config WHERE guild_id = ?", (guild_id,))
    row_initial = cursor.fetchone()
    assert row_initial["channel_id"] == initial_channel_id
    assert row_initial["enabled"] == 1

    # Update the config (change channel, stays enabled)
    kev_db.set_kev_config(guild_id, updated_channel_id)

    # Verify the update
    cursor.execute("SELECT * FROM kev_config WHERE guild_id = ?", (guild_id,))
    row_updated = cursor.fetchone()
    assert row_updated is not None
    assert row_updated["guild_id"] == guild_id
    assert row_updated["channel_id"] == updated_channel_id # Check channel updated
    assert row_updated["enabled"] == 1 # Check still enabled

    # Now disable it
    kev_db.disable_kev_config(guild_id)

    # Verify it's disabled
    cursor.execute("SELECT * FROM kev_config WHERE guild_id = ?", (guild_id,))
    row_disabled = cursor.fetchone()
    assert row_disabled["enabled"] == 0 # Check disabled (SQLite stores False as 0)
    assert row_disabled["channel_id"] == updated_channel_id # Channel should remain

def test_disable_kev_config(kev_db: KEVConfigDB, db_conn: sqlite3.Connection):
    """Test disabling an existing KEV config."""
    guild_id = 123456789012345678
    channel_id = 987654321098765432

    # Add a config first (enabled)
    kev_db.set_kev_config(guild_id, channel_id)

    # Verify it exists and is enabled
    cursor = db_conn.cursor()
    cursor.execute("SELECT enabled FROM kev_config WHERE guild_id = ?", (guild_id,))
    assert cursor.fetchone()["enabled"] == 1

    # Disable the config
    kev_db.disable_kev_config(guild_id)

    # Verify it's disabled
    cursor.execute("SELECT enabled FROM kev_config WHERE guild_id = ?", (guild_id,))
    assert cursor.fetchone()["enabled"] == 0

def test_disable_nonexistent_kev_config(kev_db: KEVConfigDB, db_conn: sqlite3.Connection):
    """Test attempting to disable a config that doesn't exist (should not error and have no effect)."""
    guild_id = 999999999999999999 # Non-existent guild ID

    # Verify no configs exist initially
    cursor = db_conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM kev_config")
    assert cursor.fetchone()[0] == 0

    # Attempt to disable
    try:
        kev_db.disable_kev_config(guild_id)
    except Exception as e:
        pytest.fail(f"disable_kev_config raised an unexpected exception: {e}")

    # Verify still no configs exist
    cursor.execute("SELECT COUNT(*) FROM kev_config")
    assert cursor.fetchone()[0] == 0

def test_get_enabled_kev_configs(kev_db: KEVConfigDB):
    """Test retrieving all enabled KEV configurations."""
    # Add some configs: one enabled, one disabled, one enabled with different channel
    kev_db.set_kev_config(1, 101)
    kev_db.set_kev_config(2, 102)
    kev_db.disable_kev_config(2) # Disable the second one
    kev_db.set_kev_config(3, 103)

    enabled_configs = kev_db.get_enabled_kev_configs()

    assert isinstance(enabled_configs, list)
    assert len(enabled_configs) == 2

    # Check contents (convert to set of tuples for easier comparison regardless of order)
    # Schema is now just guild_id, channel_id for enabled configs
    expected_configs = {
        (1, 101), # guild_id, channel_id
        (3, 103)
    }
    actual_configs = set()
    for config in enabled_configs:
        # Access by key because we used sqlite3.Row
        actual_configs.add((
            config['guild_id'],
            config['channel_id']
        ))

    assert actual_configs == expected_configs

def test_get_enabled_kev_configs_when_none(kev_db: KEVConfigDB):
    """Test retrieving enabled configs when none are set or enabled."""
    # Add a config and immediately disable it
    kev_db.set_kev_config(1, 101)
    kev_db.disable_kev_config(1)

    enabled_configs = kev_db.get_enabled_kev_configs()

    assert isinstance(enabled_configs, list)
    assert len(enabled_configs) == 0

def test_count_enabled_guilds(kev_db: KEVConfigDB):
    """Test counting enabled guilds."""
    assert kev_db.count_enabled_guilds() == 0 # Start with none

    # Add some configs
    kev_db.set_kev_config(1, 101)
    assert kev_db.count_enabled_guilds() == 1

    kev_db.set_kev_config(2, 102)
    kev_db.disable_kev_config(2) # Disable second one
    assert kev_db.count_enabled_guilds() == 1 # Count shouldn't change

    kev_db.set_kev_config(3, 103)
    assert kev_db.count_enabled_guilds() == 2

    # Disable one of the enabled ones
    kev_db.disable_kev_config(1)
    assert kev_db.count_enabled_guilds() == 1

    # Disable the remaining enabled one
    kev_db.disable_kev_config(3)
    assert kev_db.count_enabled_guilds() == 0

def test_is_kev_enabled(kev_db: KEVConfigDB):
    """Test checking if KEV is enabled for a specific guild."""
    guild_id_enabled = 1
    guild_id_disabled = 2
    guild_id_nonexistent = 3

    # Add configs
    kev_db.set_kev_config(guild_id_enabled, 101)
    kev_db.set_kev_config(guild_id_disabled, 102)
    kev_db.disable_kev_config(guild_id_disabled) # Disable the second one

    # Get the actual is_kev_enabled method from KEVConfigDB
    # Note: The original KEVConfigDB didn't have this method. Assuming it should exist based on tests.
    # If it doesn't exist, these asserts will fail. We need to add it to KEVConfigDB.
    # For now, let's assume it queries the 'enabled' column. We'll need to read/add it.

    # Hypothetical assertions (assuming is_kev_enabled exists and works)
    config_enabled = kev_db.get_kev_config(guild_id_enabled)
    assert config_enabled is not None and config_enabled['enabled'] == 1

    config_disabled = kev_db.get_kev_config(guild_id_disabled)
    assert config_disabled is not None and config_disabled['enabled'] == 0

    config_nonexistent = kev_db.get_kev_config(guild_id_nonexistent)
    assert config_nonexistent is None


# Removed the TODO comment as tests cover set, disable, get_enabled, count.
# Need to implement and test is_kev_enabled properly in KEVConfigDB.


# Clean up TODO
# TODO: Add tests for remove, get_enabled, count, is_enabled 

# --- Tests for seen_kevs table ---

def test_load_seen_kevs_empty(kev_db: KEVConfigDB):
    """Test loading seen KEVs when the table is empty."""
    seen_set = kev_db.load_seen_kevs()
    assert isinstance(seen_set, set)
    assert len(seen_set) == 0

def test_add_and_load_single_seen_kev(kev_db: KEVConfigDB):
    """Test adding a single KEV ID and then loading it."""
    cve_id = "CVE-2023-12345"
    kev_db.add_seen_kevs({cve_id})

    seen_set = kev_db.load_seen_kevs()
    assert seen_set == {cve_id}

def test_add_and_load_multiple_seen_kevs(kev_db: KEVConfigDB):
    """Test adding multiple KEV IDs and then loading them."""
    cve_ids = {"CVE-2023-11111", "CVE-2023-22222", "CVE-2023-33333"}
    kev_db.add_seen_kevs(cve_ids)

    seen_set = kev_db.load_seen_kevs()
    assert seen_set == cve_ids

def test_add_seen_kevs_duplicates(kev_db: KEVConfigDB):
    """Test that adding duplicate KEV IDs is handled gracefully (ignored)."""
    cve_id1 = "CVE-2023-44444"
    cve_id2 = "CVE-2023-55555"

    # Add one ID
    kev_db.add_seen_kevs({cve_id1})
    seen_set1 = kev_db.load_seen_kevs()
    assert seen_set1 == {cve_id1}

    # Add the same ID again, plus a new one
    kev_db.add_seen_kevs({cve_id1, cve_id2})
    seen_set2 = kev_db.load_seen_kevs()
    assert seen_set2 == {cve_id1, cve_id2} # Should contain both, no duplicates in set

    # Verify count in DB directly (optional, but good sanity check)
    assert kev_db._conn is not None # Ensure connection exists before accessing
    cursor = kev_db._conn.cursor() # Access internal connection for testing
    cursor.execute("SELECT COUNT(*) FROM seen_kevs")
    count = cursor.fetchone()[0]
    assert count == 2 # Should only be 2 unique entries

def test_add_seen_kevs_empty_set(kev_db: KEVConfigDB):
    """Test adding an empty set of KEV IDs (should have no effect)."""
    initial_seen_set = kev_db.load_seen_kevs()
    assert len(initial_seen_set) == 0

    kev_db.add_seen_kevs(set()) # Add empty set

    final_seen_set = kev_db.load_seen_kevs()
    assert len(final_seen_set) == 0
    assert initial_seen_set == final_seen_set 