import "dotenv/config";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";

const password = process.env.ADMIN_PASSWORD;
if (!password) {
  console.error("ADMIN_PASSWORD is not set. Put it in .env and run npm run seed-admin again.");
  process.exit(1);
}

const db = new Database("plainly.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const hash = await bcrypt.hash(password, 12);
const existing = db.prepare("SELECT id FROM users WHERE username = ?").get("Daniel");

if (existing) {
  db.prepare("UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?")
    .run(hash, existing.id);
  console.log("Daniel's password was updated.");
} else {
  db.prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)")
    .run("Daniel", hash);
  console.log("Daniel was created as the admin.");
}

db.close();
