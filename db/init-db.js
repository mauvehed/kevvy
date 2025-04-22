'use strict';

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Ensure the data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`Created data directory: ${dataDir}`)
}

const dbPath = path.join(dataDir, 'kevvy-web.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        return;
    }
    console.log(`Connected to the SQLite database at ${dbPath}`);
});

db.serialize(() => {
    // --- Status Table ---
    db.run(`
        CREATE TABLE IF NOT EXISTS status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            bot_id TEXT,
            bot_name TEXT,
            guild_count INTEGER,
            latency_ms REAL,
            uptime_seconds INTEGER,
            shard_id INTEGER,
            shard_count INTEGER,
            is_ready BOOLEAN,
            is_closed BOOLEAN,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error("Error creating status table:", err.message);
        } else {
            console.log("'status' table checked/created successfully.");
        }
    });

    // --- Stats Table ---
    db.run(`
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, /* Timestamp from the bot */
            cve_lookups_since_last INTEGER,
            kev_alerts_sent_since_last INTEGER,
            messages_processed_since_last INTEGER,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error("Error creating stats table:", err.message);
        } else {
            console.log("'stats' table checked/created successfully.");
        }
    });
});

db.close((err) => {
    if (err) {
        console.error('Error closing database connection:', err.message);
    } else {
        console.log('Database connection closed.');
    }
}); 