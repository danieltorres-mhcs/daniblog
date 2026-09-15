import "dotenv/config";
import bcrypt from "bcryptjs";
import { createClient } from "@libsql/client";

if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error("TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required.");
  process.exit(1);
}
const password = process.env.ADMIN_PASSWORD;
if (!password) {
  console.error("ADMIN_PASSWORD is not set.");
  process.exit(1);
}
const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });

await db.execute(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  can_post INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
await db.execute(`CREATE TABLE IF NOT EXISTS articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'published',
  review_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

const hash = await bcrypt.hash(password, 12);
const existing = (await db.execute({ sql: "SELECT id FROM users WHERE username = ? COLLATE NOCASE", args: ["Daniel"] })).rows[0];
if (existing) {
  await db.execute({ sql: "UPDATE users SET password_hash = ?, is_admin = 1, can_post = 1 WHERE id = ?", args: [hash, existing.id] });
  console.log("Daniel's password was updated.");
} else {
  await db.execute({ sql: "INSERT INTO users (username, password_hash, is_admin, can_post) VALUES (?, ?, 1, 1)", args: ["Daniel", hash] });
  console.log("Daniel was created as the admin.");
}
