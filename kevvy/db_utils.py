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
            # Migration check for 'enabled' column in kev_config
            cursor.execute("PRAGMA table_info(kev_config)")
            kev_columns = {column['name'] for column in cursor.fetchall()}
            if 'enabled' not in kev_columns:
                logger.info("Adding 'enabled' column to kev_config table.")
                cursor.execute("ALTER TABLE kev_config ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seen_kevs (
                    cve_id TEXT PRIMARY KEY
                )
            """)

            # --- CVE Guild Config Table --- 
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_guild_config (
                    guild_id INTEGER PRIMARY KEY,
                    enabled BOOLEAN DEFAULT true,
                    verbose_mode BOOLEAN DEFAULT false,
                    severity_threshold TEXT DEFAULT 'all',
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # --- Migration: Rename old cve_channel_config table IF it exists AND new one doesn't ---
            try:
                # Check existence of both tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_channel_config'")
                old_table_exists = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_guild_config'")
                new_table_exists = cursor.fetchone() is not None

                if old_table_exists and not new_table_exists:
                    logger.warning("Found old 'cve_channel_config' table and no 'cve_guild_config'. Attempting rename and column adjustments.")
                    # Rename table
                    cursor.execute("ALTER TABLE cve_channel_config RENAME TO cve_guild_config")

                    # Check and Add columns if they don't exist in the renamed table
                    cursor.execute("PRAGMA table_info(cve_guild_config)")
                    guild_config_columns = {column['name'] for column in cursor.fetchall()}

                    if 'enabled' not in guild_config_columns:
                         cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN enabled BOOLEAN DEFAULT true")
                    if 'verbose_mode' not in guild_config_columns:
                         cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN verbose_mode BOOLEAN DEFAULT false")
                    if 'severity_threshold' not in guild_config_columns:
                         cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN severity_threshold TEXT DEFAULT 'all'")
                    if 'last_updated' not in guild_config_columns:
                         cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                    
                    logger.info("Successfully renamed 'cve_channel_config' to 'cve_guild_config' and checked columns.")
                
                elif old_table_exists and new_table_exists:
                    logger.warning("Both 'cve_channel_config' and 'cve_guild_config' tables exist. Skipping rename. The old table may need manual review or deletion.")
                    # Consider adding logic here to attempt data migration if needed, or just leave the warning.
                
                # elif not old_table_exists:
                    # logger.debug("Old 'cve_channel_config' table not found. No rename needed.")
                 
            except sqlite3.Error as mig_err:
                logger.error(f"Error during cve_channel_config migration check/rename: {mig_err}", exc_info=True)
                # Depending on the error, might need manual intervention
            
            # Ensure the columns exist in cve_guild_config even if migration wasn't needed/failed
            # (This handles fresh installs or cases where migration failed partially)
            try:
                 cursor.execute("PRAGMA table_info(cve_guild_config)")
                 guild_config_columns = {column['name'] for column in cursor.fetchall()}
                 if 'enabled' not in guild_config_columns:
                      cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN enabled BOOLEAN DEFAULT true")
                 if 'verbose_mode' not in guild_config_columns:
                      cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN verbose_mode BOOLEAN DEFAULT false")
                 if 'severity_threshold' not in guild_config_columns:
                      cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN severity_threshold TEXT DEFAULT 'all'")
                 if 'last_updated' not in guild_config_columns:
                      cursor.execute("ALTER TABLE cve_guild_config ADD COLUMN last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            except sqlite3.Error as add_col_err:
                 logger.error(f"Error ensuring columns exist in cve_guild_config: {add_col_err}", exc_info=True)

            # --- Per-Channel CVE Config Table ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_channel_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    enabled BOOLEAN DEFAULT true,
                    verbose_mode BOOLEAN DEFAULT NULL,
                    severity_threshold TEXT DEFAULT NULL,
                    alert_format TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(guild_id, channel_id)
                )
            """)
            # Migration check for columns in cve_channel_configs (add if missing)
            try:
                 cursor.execute("PRAGMA table_info(cve_channel_configs)")
                 channel_configs_columns = {column['name'] for column in cursor.fetchall()}
                 if 'enabled' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN enabled BOOLEAN DEFAULT true")
                 if 'verbose_mode' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN verbose_mode BOOLEAN DEFAULT NULL")
                 if 'severity_threshold' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN severity_threshold TEXT DEFAULT NULL")
                 if 'alert_format' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN alert_format TEXT DEFAULT NULL")
                 if 'created_at' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                 if 'updated_at' not in channel_configs_columns:
                      cursor.execute("ALTER TABLE cve_channel_configs ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                 # Check for UNIQUE constraint (harder to check/add reliably, assuming CREATE TABLE handles it)
            except sqlite3.Error as add_col_err_ch:
                 logger.error(f"Error ensuring columns exist in cve_channel_configs: {add_col_err_ch}", exc_info=True)


            # --- CVE Monitoring History Table ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_monitoring_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER,
                    channel_id INTEGER,
                    cve_id TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # --- KEV Latest Queries Table ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kev_latest_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER,
                    user_id INTEGER,
                    query_params TEXT, 
                    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            logger.info("Database tables initialized/verified successfully.")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}", exc_info=True)
            # Consider raising the exception or handling it more gracefully depending on application needs

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

    # --- Methods for Global CVE Guild Config (Formerly CVE Channel Config) ---
    def set_cve_guild_config(self, guild_id: int, enabled: bool, verbose_mode: bool, severity_threshold: SeverityLevel):
        """Sets or updates the global CVE configuration settings for a guild."""
        if not self._conn:
             logger.error("No DB connection to set CVE guild config.")
             return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO cve_guild_config (guild_id, enabled, verbose_mode, severity_threshold, last_updated)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(guild_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    verbose_mode = excluded.verbose_mode,
                    severity_threshold = excluded.severity_threshold,
                    last_updated = CURRENT_TIMESTAMP;
            """, (guild_id, enabled, verbose_mode, severity_threshold))
            logger.info(f"Set/Updated global CVE config for guild {guild_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting global CVE config for guild {guild_id}: {e}", exc_info=True)

    def get_cve_guild_config(self, guild_id: int) -> Optional[Dict]:
        """Retrieves the global CVE configuration for a specific guild."""
        if not self._conn:
             logger.error("No DB connection to get CVE guild config.")
             return None
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT guild_id, enabled, verbose_mode, severity_threshold
                FROM cve_guild_config
                WHERE guild_id = ?
            """, (guild_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error getting CVE guild config for guild {guild_id}: {e}", exc_info=True)
            return None

    def update_cve_guild_enabled(self, guild_id: int, enabled: bool):
        """Updates only the enabled status for the global CVE config."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                UPDATE cve_guild_config SET enabled = ?, last_updated = CURRENT_TIMESTAMP WHERE guild_id = ?
            """, (enabled, guild_id))
            logger.info(f"Updated global CVE enabled status for guild {guild_id} to {enabled}.")
        except sqlite3.Error as e:
            logger.error(f"Error updating CVE guild enabled status for {guild_id}: {e}", exc_info=True)

    def update_cve_guild_verbose_mode(self, guild_id: int, verbose_mode: bool):
        """Updates the global verbose mode for a guild."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                 INSERT INTO cve_guild_config (guild_id, verbose_mode, last_updated)
                 VALUES (?, ?, CURRENT_TIMESTAMP)
                 ON CONFLICT(guild_id) DO UPDATE SET
                     verbose_mode = excluded.verbose_mode,
                     last_updated = CURRENT_TIMESTAMP;
            """, (guild_id, verbose_mode))
            logger.info(f"Set/Updated global CVE verbose mode for guild {guild_id} to {verbose_mode}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting global CVE verbose mode for {guild_id}: {e}", exc_info=True)

    def update_cve_guild_severity_threshold(self, guild_id: int, threshold: SeverityLevel):
        """Updates the global severity threshold for a guild."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                 INSERT INTO cve_guild_config (guild_id, severity_threshold, last_updated)
                 VALUES (?, ?, CURRENT_TIMESTAMP)
                 ON CONFLICT(guild_id) DO UPDATE SET
                     severity_threshold = excluded.severity_threshold,
                     last_updated = CURRENT_TIMESTAMP;
            """, (guild_id, threshold))
            logger.info(f"Set/Updated global CVE severity threshold for guild {guild_id} to {threshold}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting global CVE severity threshold for {guild_id}: {e}", exc_info=True)

    # --- NEW Methods for Per-Channel CVE Configs ---

    def add_or_update_cve_channel(self, guild_id: int, channel_id: int, enabled: bool = True, verbose_mode: Optional[bool] = None, severity_threshold: Optional[SeverityLevel] = None, alert_format: Optional[str] = None):
        """Adds a new channel config or updates an existing one."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO cve_channel_configs (guild_id, channel_id, enabled, verbose_mode, severity_threshold, alert_format, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(guild_id, channel_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    verbose_mode = excluded.verbose_mode,
                    severity_threshold = excluded.severity_threshold,
                    alert_format = excluded.alert_format,
                    updated_at = CURRENT_TIMESTAMP;
            """, (guild_id, channel_id, enabled, verbose_mode, severity_threshold, alert_format))
            logger.info(f"Added/Updated CVE config for channel {channel_id} in guild {guild_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error adding/updating CVE channel config for {channel_id} in {guild_id}: {e}", exc_info=True)

    def remove_cve_channel(self, guild_id: int, channel_id: int):
        """Removes a specific channel configuration."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM cve_channel_configs WHERE guild_id = ? AND channel_id = ?", (guild_id, channel_id))
            logger.info(f"Removed CVE config for channel {channel_id} in guild {guild_id}.")
        except sqlite3.Error as e:
            logger.error(f"Error removing CVE channel config for {channel_id} in {guild_id}: {e}", exc_info=True)

    def get_cve_channel_config(self, guild_id: int, channel_id: int) -> Optional[Dict]:
        """Retrieves the specific configuration for a single channel."""
        if not self._conn: return None
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT id, guild_id, channel_id, enabled, verbose_mode, severity_threshold, alert_format
                FROM cve_channel_configs
                WHERE guild_id = ? AND channel_id = ?
            """, (guild_id, channel_id))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error getting CVE channel config for {channel_id} in {guild_id}: {e}", exc_info=True)
            return None

    def get_all_cve_channel_configs_for_guild(self, guild_id: int) -> List[Dict]:
        """Retrieves all specific channel configurations for a guild."""
        if not self._conn: return []
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT id, guild_id, channel_id, enabled, verbose_mode, severity_threshold, alert_format
                FROM cve_channel_configs
                WHERE guild_id = ?
            """, (guild_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error getting all CVE channel configs for guild {guild_id}: {e}", exc_info=True)
            return []

    def set_channel_verbosity(self, guild_id: int, channel_id: int, verbose_mode: Optional[bool]):
        """Sets or unsets the verbose mode override for a specific channel."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO cve_channel_configs (guild_id, channel_id, verbose_mode, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(guild_id, channel_id) DO UPDATE SET
                    verbose_mode = excluded.verbose_mode,
                    updated_at = CURRENT_TIMESTAMP;
            """, (guild_id, channel_id, verbose_mode))
            status = "set to " + str(verbose_mode) if verbose_mode is not None else "unset (use global)"
            logger.info(f"Verbosity for channel {channel_id} in guild {guild_id} {status}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting verbosity for channel {channel_id} in {guild_id}: {e}", exc_info=True)

    def set_all_channel_verbosity(self, guild_id: int, verbose_mode: bool):
        """Sets the verbose mode for ALL existing channel configs in a guild."""
        if not self._conn: return
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                UPDATE cve_channel_configs
                SET verbose_mode = ?, updated_at = CURRENT_TIMESTAMP
                WHERE guild_id = ?;
            """, (verbose_mode, guild_id))
            logger.info(f"Set verbosity for ALL channels in guild {guild_id} to {verbose_mode}.")
        except sqlite3.Error as e:
            logger.error(f"Error setting verbosity for all channels in {guild_id}: {e}", exc_info=True)

    def get_effective_verbosity(self, guild_id: int, channel_id: int) -> bool:
        """Gets the effective verbosity for a channel, checking channel override then global default."""
        channel_config = self.get_cve_channel_config(guild_id, channel_id)
        if channel_config and channel_config['verbose_mode'] is not None:
            # Specific channel setting exists and is not NULL
            return bool(channel_config['verbose_mode'])

        # Fallback to global setting
        guild_config = self.get_cve_guild_config(guild_id)
        # Default to False (non-verbose) if no global config found or verbose_mode isn't set
        return bool(guild_config['verbose_mode']) if guild_config and 'verbose_mode' in guild_config else False

    # --- Methods for Logging ---
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
