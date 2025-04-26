import sqlite3
import logging
import os
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_config.db')

class KEVConfigDB:
    """Handles database operations for CISA KEV and CVE Response per-guild configurations."""

    _conn: Optional[sqlite3.Connection]

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        """Initializes the database connection.

        Args:
            db_path: Path to the SQLite database file.
        """
        db_dir = os.path.dirname(db_path)
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
                logger.info(f"Created data directory: {db_dir}")
            except OSError as e:
                logger.error(f"Failed to create data directory {db_dir}: {e}")

        self.db_path = db_path
        self._conn = None
        self._ensure_connection()
        self._initialize_db()
        self._initialize_cve_response_settings_table()

    def _ensure_connection(self):
        """Establishes connection to the database if not already connected."""
        if self._conn is None:
            try:
                # isolation_level=None enables autocommit mode
                self._conn = sqlite3.connect(self.db_path, isolation_level=None)
                # Use Row factory for dictionary-like access
                self._conn.row_factory = sqlite3.Row
                logger.info(f"Connected to database: {self.db_path}")
            except sqlite3.Error as e:
                logger.error(f"Database connection error to {self.db_path}: {e}", exc_info=True)
                raise

    def _initialize_db(self):
        """Creates the KEV-related tables if they don't exist."""
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
            # Migration check for 'enabled' column
            cursor.execute("PRAGMA table_info(kev_config)")
            columns = [column['name'] for column in cursor.fetchall()]
            if 'enabled' not in columns:
                logger.info("Adding 'enabled' column to kev_config table.")
                cursor.execute("ALTER TABLE kev_config ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seen_kevs (
                    cve_id TEXT PRIMARY KEY
                )
            """)

            logger.debug("KEV-related database tables initialized successfully.")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error (KEV tables): {e}", exc_info=True)

    def _initialize_cve_response_settings_table(self):
        """Creates the CVE response settings table if it doesn't exist."""
        if not self._conn:
            logger.error("Cannot initialize CVE response settings table, no connection.")
            return

        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_response_settings (
                    guild_id INTEGER PRIMARY KEY,
                    response_mode TEXT NOT NULL
                )
            """)
            # Note: response_mode can store a channel ID (as text) or the literal string "all"
            # Absence of a row implies CVE responses are disabled for the guild.
            logger.debug("CVE response settings table initialized successfully.")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error (CVE response settings table): {e}", exc_info=True)

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
            cursor.execute("""
                UPDATE kev_config
                SET enabled = 0
                WHERE guild_id = ?;
            """, (guild_id,))
            if cursor.rowcount > 0:
                logger.info(f"Disabled KEV config for guild {guild_id}.")
            else:
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
             return set()
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT cve_id FROM seen_kevs")
            rows = cursor.fetchall()
            seen_set = {row['cve_id'] for row in rows}
            logger.info(f"Loaded {len(seen_set)} seen KEV IDs from database.")
            return seen_set
        except sqlite3.Error as e:
            logger.error(f"Error loading seen KEVs: {e}", exc_info=True)
            return set()

    def add_seen_kevs(self, cve_ids: set[str]):
        """Adds a set of KEV IDs to the seen list in the database."""
        if not self._conn:
            logger.error("No DB connection to add seen KEVs.")
            return
        if not cve_ids:
            return

        try:
            cursor = self._conn.cursor()
            data_to_insert = [(cve_id,) for cve_id in cve_ids]
            # Use INSERT OR IGNORE to avoid errors if ID already exists
            cursor.executemany("INSERT OR IGNORE INTO seen_kevs (cve_id) VALUES (?)", data_to_insert)
            logger.debug(f"Attempted to add {len(cve_ids)} KEV IDs to seen list in DB (ignored duplicates).")
        except sqlite3.Error as e:
            logger.error(f"Error adding seen KEVs: {e}", exc_info=True)

    def count_enabled_guilds(self) -> int:
        """Counts the number of distinct guilds with KEV monitoring enabled."""
        if not self._conn:
            logger.error("Cannot count enabled KEV guilds: Database connection is not available.")
            return 0
        try:
            cursor = self._conn.cursor()
            cursor.execute('''
                SELECT COUNT(DISTINCT guild_id) FROM kev_config WHERE enabled = 1
            ''')
            result = cursor.fetchone()
            return result[0] if result else 0
        except sqlite3.Error as e:
            logger.error(f"Database error counting enabled KEV guilds: {e}", exc_info=True)
            return 0 # Return 0 on error

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
