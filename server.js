// --- Database Connection ---
// Ensure the init script has been run (`yarn db:init`)
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
        console.error(`Error connecting to database ${dbPath}:`, err.message);
        console.error('Did you forget to run \`yarn db:init\`?');
        process.exit(1);
    }
    console.log(`Successfully connected to the SQLite database at ${dbPath}`);
}); 