import sqlite3
import logging
import os
from typing import Optional, List, Tuple, Dict

logger = logging.getLogger(__name__)

# Default path for the database file within the project structure
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_config.db')

class KEVConfigDB:
    """Handles database operations for CISA KEV per-guild configurations."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        """Initializes the database connection.

        Args:
            db_path: Path to the SQLite database file.
        """
        # Ensure the data directory exists
        db_dir = os.path.dirname(db_path)
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
                logger.info(f"Created data directory: {db_dir}")
            except OSError as e:
                logger.error(f"Failed to create data directory {db_dir}: {e}")
                # Fallback or raise error?
                # For now, let's allow sqlite3 to handle the error if path is invalid

        self.db_path = db_path
        self._conn = None
        self._ensure_connection()
        self._initialize_db()

    def _ensure_connection(self):
        """Establishes connection to the database if not already connected."""
        if self._conn is None:
            try:
                # isolation_level=None enables autocommit mode, simplifying single operations
                self._conn = sqlite3.connect(self.db_path, isolation_level=None)
                # Use Row factory for dictionary-like access
                self._conn.row_factory = sqlite3.Row
                logger.info(f"Connected to database: {self.db_path}")
            except sqlite3.Error as e:
                logger.error(f"Database connection error to {self.db_path}: {e}", exc_info=True)
                # Consider raising a custom exception or handling differently
                raise

    def _initialize_db(self):
        """Creates the necessary table if it doesn't exist."""
        if not self._conn:
            logger.error("Cannot initialize DB, no connection.")
            return
            
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kev_config (
                    guild_id INTEGER PRIMARY KEY,
                    channel_id INTEGER NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 0
                )
            """)
            # Check if 'enabled' column exists (for potential migrations from older schemas)
            cursor.execute("PRAGMA table_info(kev_config)")
            columns = [column['name'] for column in cursor.fetchall()]
            if 'enabled' not in columns:
                logger.info("Adding 'enabled' column to kev_config table.")
                cursor.execute("ALTER TABLE kev_config ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0")
            
            # --- Initialize seen_kevs table --- 
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seen_kevs (
                    cve_id TEXT PRIMARY KEY
                )
            """)
            # ----------------------------------

            logger.debug("Database tables initialized successfully.")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}", exc_info=True)

    def set_kev_config(self, guild_id: int, channel_id: int):
        """Enables or updates KEV monitoring config for a guild."""
        if not self._conn:
             logger.error("No DB connection to set KEV config.")
             return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO kev_config (guild_id, channel_id, enabled)
                VALUES (?, ?, 1)
                ON CONFLICT(guild_id) DO UPDATE SET
                    channel_id = excluded.channel_id,
                    enabled = 1;
            """, (guild_id, channel_id))
            logger.info(f"Enabled/Updated KEV config for guild {guild_id} to channel {channel_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting KEV config for guild {guild_id}: {e}", exc_info=True)

    def disable_kev_config(self, guild_id: int):
        """Disables KEV monitoring for a guild."""
        if not self._conn:
             logger.error("No DB connection to disable KEV config.")
             return
        try:
            cursor = self._conn.cursor()
            # Update enabled to 0 if the guild exists, otherwise do nothing
            cursor.execute("""
                UPDATE kev_config 
                SET enabled = 0 
                WHERE guild_id = ?;
            """, (guild_id,))
            if cursor.rowcount > 0:
                logger.info(f"Disabled KEV config for guild {guild_id}.")
            else:
                # If no row was updated, it means the guild wasn't configured
                logger.info(f"Attempted to disable KEV config for guild {guild_id}, but it was not configured.")
        except sqlite3.Error as e:
            logger.error(f"Error disabling KEV config for guild {guild_id}: {e}", exc_info=True)

    def get_kev_config(self, guild_id: int) -> Optional[Dict]:
        """Retrieves the KEV config for a specific guild."""
        if not self._conn:
             logger.error("No DB connection to get KEV config.")
             return None
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT guild_id, channel_id, enabled FROM kev_config WHERE guild_id = ?", (guild_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error getting KEV config for guild {guild_id}: {e}", exc_info=True)
            return None

    def get_enabled_kev_configs(self) -> List[Dict]:
        """Retrieves all configurations where KEV monitoring is enabled."""
        if not self._conn:
             logger.error("No DB connection to get enabled KEV configs.")
             return []
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT guild_id, channel_id FROM kev_config WHERE enabled = 1")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error getting enabled KEV configs: {e}", exc_info=True)
            return []

    # --- Methods for seen KEVs --- 

    def load_seen_kevs(self) -> set[str]:
        """Loads all previously seen KEV IDs from the database."""
        if not self._conn:
             logger.error("No DB connection to load seen KEVs.")
             return set() # Return empty set if no DB connection
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT cve_id FROM seen_kevs")
            rows = cursor.fetchall()
            seen_set = {row['cve_id'] for row in rows}
            logger.info(f"Loaded {len(seen_set)} seen KEV IDs from database.")
            return seen_set
        except sqlite3.Error as e:
            logger.error(f"Error loading seen KEVs: {e}", exc_info=True)
            return set() # Return empty set on error
            
    def add_seen_kevs(self, cve_ids: set[str]):
        """Adds a set of KEV IDs to the seen list in the database."""
        if not self._conn:
            logger.error("No DB connection to add seen KEVs.")
            return
        if not cve_ids:
            return # Nothing to add
            
        try:
            cursor = self._conn.cursor()
            # Prepare data as list of tuples for executemany
            data_to_insert = [(cve_id,) for cve_id in cve_ids]
            # Use INSERT OR IGNORE to avoid errors if ID already exists
            cursor.executemany("INSERT OR IGNORE INTO seen_kevs (cve_id) VALUES (?)", data_to_insert)
            # No need to commit due to isolation_level=None
            logger.debug(f"Attempted to add {len(cve_ids)} KEV IDs to seen list in DB (ignored duplicates).")
        except sqlite3.Error as e:
            logger.error(f"Error adding seen KEVs: {e}", exc_info=True)
    # ----------------------------- 

    def close(self):
        """Closes the database connection."""
        if self._conn:
            try:
                self._conn.close()
                self._conn = None
                logger.info(f"Database connection closed for {self.db_path}.")
            except sqlite3.Error as e:
                logger.error(f"Error closing database connection {self.db_path}: {e}", exc_info=True)

    def __del__(self):
        """Ensure connection is closed when the object is destroyed."""
        self.close()

# Example usage (for testing):
# if __name__ == '__main__':
#     logging.basicConfig(level=logging.INFO)
#     db = KEVConfigDB(db_path='../data/test_bot_config.db') # Use a test DB path
#     db.set_kev_config(12345, 98765)
#     db.set_kev_config(54321, 11111)
#     db.set_kev_config(12345, 55555) # Update
#     config1 = db.get_kev_config(12345)
#     config2 = db.get_kev_config(54321)
#     config_none = db.get_kev_config(99999)
#     print(f"Guild 12345 Config: {config1}")
#     print(f"Guild 54321 Config: {config2}")
#     print(f"Guild 99999 Config: {config_none}")
#     enabled_configs = db.get_enabled_kev_configs()
#     print(f"Enabled Configs (Before Disable): {enabled_configs}")
#     db.disable_kev_config(54321)
#     config2_after = db.get_kev_config(54321)
#     print(f"Guild 54321 Config (After Disable): {config2_after}")
#     enabled_configs_after = db.get_enabled_kev_configs()
#     print(f"Enabled Configs (After Disable): {enabled_configs_after}")
#     db.close() 