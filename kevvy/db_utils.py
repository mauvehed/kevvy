import sqlite3
import logging
import os
from typing import Optional, List, Dict, Any, Literal
import json

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_config.db')
SeverityLevel = Literal["critical", "high", "medium", "low", "all"]

class KEVConfigDB:
    """Handles database operations for CISA KEV and CVE per-guild configurations."""

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
        """Creates the necessary tables if they don't exist."""
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

            # --- NEW Tables from PRD ---

            # --- CVE Channel Config Table (as per PRD Section 4) ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_channel_config (
                    guild_id INTEGER PRIMARY KEY,
                    channel_id INTEGER,
                    enabled BOOLEAN DEFAULT true,
                    verbose_mode BOOLEAN DEFAULT false,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migration check for 'severity_threshold' column (as per PRD Section 3.1.5)
            cursor.execute("PRAGMA table_info(cve_channel_config)")
            cve_config_columns = [column['name'] for column in cursor.fetchall()]
            if 'severity_threshold' not in cve_config_columns:
                logger.info("Adding 'severity_threshold' column to cve_channel_config table.")
                cursor.execute("ALTER TABLE cve_channel_config ADD COLUMN severity_threshold TEXT DEFAULT 'all'")

            # --- CVE Monitoring History Table (as per PRD Section 4) ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_monitoring_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER,
                    channel_id INTEGER,
                    cve_id TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    -- Optional: Add FOREIGN KEY if needed and ensure kev_config exists
                    -- FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
                )
            """)

            # --- KEV Latest Queries Table (as per PRD Section 4) ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kev_latest_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER,
                    user_id INTEGER,
                    query_params TEXT, -- JSON string of parameters
                    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    -- Optional: Add FOREIGN KEY if needed and ensure kev_config exists
                    -- FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
                )
            """)
            # --- End NEW Tables ---

            logger.info("Database tables initialized/verified successfully.")
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

    # --- NEW Methods for CVE Channel Config ---
    def set_cve_channel_config(self, guild_id: int, channel_id: int, enabled: bool = True, verbose_mode: bool = False, severity_threshold: SeverityLevel = 'all'):
        """Sets or updates the CVE channel configuration for a guild."""
        if not self._conn:
             logger.error("No DB connection to set CVE channel config.")
             return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO cve_channel_config (guild_id, channel_id, enabled, verbose_mode, severity_threshold, last_updated)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(guild_id) DO UPDATE SET
                    channel_id = excluded.channel_id,
                    enabled = excluded.enabled,
                    verbose_mode = excluded.verbose_mode,
                    severity_threshold = excluded.severity_threshold,
                    last_updated = CURRENT_TIMESTAMP;
            """, (guild_id, channel_id, enabled, verbose_mode, severity_threshold))
            logger.info(f"Set/Updated CVE channel config for guild {guild_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting CVE channel config for guild {guild_id}: {e}", exc_info=True)

    def get_cve_channel_config(self, guild_id: int) -> Optional[Dict]:
        """Retrieves the CVE channel configuration for a specific guild."""
        if not self._conn:
             logger.error("No DB connection to get CVE channel config.")
             return None
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT guild_id, channel_id, enabled, verbose_mode, severity_threshold, last_updated FROM cve_channel_config WHERE guild_id = ?", (guild_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error getting CVE channel config for guild {guild_id}: {e}", exc_info=True)
            return None

    def disable_cve_channel_config(self, guild_id: int):
        """Disables CVE monitoring for a guild."""
        if not self._conn:
             logger.error("No DB connection to disable CVE channel config.")
             return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                UPDATE cve_channel_config
                SET enabled = 0, last_updated = CURRENT_TIMESTAMP
                WHERE guild_id = ?;
            """, (guild_id,))
            if cursor.rowcount > 0:
                logger.info(f"Disabled CVE channel config for guild {guild_id}.")
            else:
                 # If not present, insert a disabled record
                 self.set_cve_channel_config(guild_id=guild_id, channel_id=0, enabled=False) # Use 0 or None for channel_id if disabled? Let's use 0.
                 logger.info(f"Set CVE channel config to disabled for guild {guild_id} (was not previously configured).")

        except sqlite3.Error as e:
            logger.error(f"Error disabling CVE channel config for guild {guild_id}: {e}", exc_info=True)

    def set_cve_severity_threshold(self, guild_id: int, threshold: SeverityLevel):
        """Sets the severity threshold for CVE alerts for a specific guild."""
        if not self._conn:
             logger.error("No DB connection to set CVE severity threshold.")
             return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                UPDATE cve_channel_config
                SET severity_threshold = ?, last_updated = CURRENT_TIMESTAMP
                WHERE guild_id = ?;
            """, (threshold, guild_id))
            if cursor.rowcount > 0:
                logger.info(f"Set CVE severity threshold to '{threshold}' for guild {guild_id}.")
            else:
                logger.warning(f"Attempted to set CVE severity threshold for guild {guild_id}, but no config exists. Threshold not set.")
        except sqlite3.Error as e:
            logger.error(f"Error setting CVE severity threshold for guild {guild_id}: {e}", exc_info=True)

    # --- NEW Methods for History / Logging ---
    def log_cve_alert_history(self, guild_id: int, channel_id: int, cve_id: str):
        """Logs when a CVE alert was detected/sent for a guild/channel."""
        if not self._conn:
            logger.error("No DB connection to log CVE alert history.")
            return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO cve_monitoring_history (guild_id, channel_id, cve_id, detected_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP);
            """, (guild_id, channel_id, cve_id))
            logger.debug(f"Logged CVE {cve_id} alert history for guild {guild_id} in channel {channel_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error logging CVE alert history for guild {guild_id}: {e}", exc_info=True)

    def log_kev_latest_query(self, guild_id: int, user_id: int, query_params: Dict[str, Any]):
        """Logs a `/kev latest` query."""
        if not self._conn:
            logger.error("No DB connection to log KEV latest query.")
            return
        try:
            params_json = json.dumps(query_params)
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO kev_latest_queries (guild_id, user_id, query_params, queried_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP);
            """, (guild_id, user_id, params_json))
            logger.debug(f"Logged /kev latest query for user {user_id} in guild {guild_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error logging /kev latest query for guild {guild_id}: {e}", exc_info=True)
        except json.JSONDecodeError as e:
             logger.error(f"Error serializing query params to JSON for KEV latest query log: {e}", exc_info=True)

    # --- General Methods ---
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
