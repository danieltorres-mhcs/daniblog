import "dotenv/config";
import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import { marked } from "marked";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}
const port = Number(process.env.PORT || 3000);
const dataDir = path.resolve(process.env.DATA_DIR || __dirname);
fs.mkdirSync(dataDir, { recursive: true });

if (!process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is required in .env");
  process.exit(1);
}

const db = new Database(path.join(dataDir, "plainly.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    parent_id INTEGER,
    reply_to_user_id INTEGER,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(parent_id) REFERENCES comments(id) ON DELETE CASCADE,
    FOREIGN KEY(reply_to_user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migrate existing databases created before threaded replies were added.
const commentColumns = db.prepare("PRAGMA table_info(comments)").all().map(row => row.name);
if (!commentColumns.includes("parent_id")) {
  db.exec("ALTER TABLE comments ADD COLUMN parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE");
}
if (!commentColumns.includes("reply_to_user_id")) {
  db.exec("ALTER TABLE comments ADD COLUMN reply_to_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL");
}
db.exec("CREATE INDEX IF NOT EXISTS idx_comments_article_parent ON comments(article_id, parent_id, id)");

// Ensure the Daniel administrator account exists in the same database used by the app.
// ADMIN_PASSWORD is supplied by the hosting environment (for example, Render).
if (process.env.ADMIN_PASSWORD) {
  const adminPassword = process.env.ADMIN_PASSWORD;
  const adminHash = await bcrypt.hash(adminPassword, 12);
  const existingAdmin = db.prepare("SELECT id FROM users WHERE username = ?").get("Daniel");

  if (existingAdmin) {
    db.prepare("UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?")
      .run(adminHash, existingAdmin.id);
    console.log("Daniel administrator account verified.");
  } else {
    db.prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)")
      .run("Daniel", adminHash);
    console.log("Daniel administrator account created.");
  }
} else {
  console.warn("ADMIN_PASSWORD is not set; Daniel's admin account was not created or updated.");
}

const SQLiteStore = SQLiteStoreFactory(session);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: dataDir }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
app.use(express.static(path.join(__dirname, "public")));

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare(
    "SELECT id, username, is_admin FROM users WHERE id = ?"
  ).get(req.session.userId) || null;
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in." });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user?.is_admin) return res.status(403).json({ error: "Admin access required." });
  req.user = user;
  next();
}

// Public article list
app.get("/api/articles", (req, res) => {
  const rows = db.prepare(`
    SELECT a.id, a.title, a.description, a.content, a.created_at, a.updated_at,
           (SELECT COUNT(*) FROM comments c WHERE c.article_id = a.id) AS comment_count
    FROM articles a
    ORDER BY datetime(a.created_at) DESC, a.id DESC
  `).all();
  res.json(rows);
});

// Public single article
app.get("/api/articles/:id", (req, res) => {
  const row = db.prepare(`
    SELECT id, title, description, content, created_at, updated_at
    FROM articles WHERE id = ?
  `).get(Number(req.params.id));

  if (!row) return res.status(404).json({ error: "Article not found." });

  // The client can render the markdown. Keep the source markdown here.
  res.json(row);
});

// Comments and replies
app.get("/api/articles/:id/comments", (req, res) => {
  const articleId = Number(req.params.id);
  const article = db.prepare("SELECT id FROM articles WHERE id = ?").get(articleId);
  if (!article) return res.status(404).json({ error: "Article not found." });

  const rows = db.prepare(`
    SELECT c.id, c.article_id, c.user_id, c.parent_id, c.content, c.created_at,
           u.username, reply_user.username AS reply_to_username
    FROM comments c
    JOIN users u ON u.id = c.user_id
    LEFT JOIN users reply_user ON reply_user.id = c.reply_to_user_id
    WHERE c.article_id = ?
    ORDER BY datetime(c.created_at) ASC, c.id ASC
  `).all(articleId);
  res.json(rows);
});

app.post("/api/articles/:id/comments", requireLogin, (req, res) => {
  const articleId = Number(req.params.id);
  const content = String(req.body.content || "").trim();
  const parentId = req.body.parentId == null || req.body.parentId === "" ? null : Number(req.body.parentId);
  const replyToUserId = req.body.replyToUserId == null || req.body.replyToUserId === "" ? null : Number(req.body.replyToUserId);
  const article = db.prepare("SELECT id FROM articles WHERE id = ?").get(articleId);
  if (!article) return res.status(404).json({ error: "Article not found." });
  if (!content) return res.status(400).json({ error: "Comment cannot be empty." });
  if (content.length > 5000) return res.status(400).json({ error: "Comment is too long." });

  if (parentId !== null) {
    const parent = db.prepare("SELECT id, article_id, parent_id FROM comments WHERE id = ?").get(parentId);
    if (!parent || parent.article_id !== articleId) return res.status(400).json({ error: "Reply target not found." });
    // Replies are kept in one flat reply list beneath the original comment.
    // If the target is itself a reply, its original top-level comment is used.
    const rootId = parent.parent_id || parent.id;
    if (rootId !== parentId) {
      // parentId is the reply being answered; convert it to the root below.
    }
    if (replyToUserId !== null) {
      const replyUser = db.prepare("SELECT id FROM users WHERE id = ?").get(replyToUserId);
      if (!replyUser) return res.status(400).json({ error: "Reply user not found." });
    }
    const result = db.prepare(`
      INSERT INTO comments (article_id, user_id, parent_id, reply_to_user_id, content)
      VALUES (?, ?, ?, ?, ?)
    `).run(articleId, req.user.id, rootId, replyToUserId, content);
    return res.status(201).json({ id: result.lastInsertRowid });
  }

  const result = db.prepare(`
    INSERT INTO comments (article_id, user_id, parent_id, reply_to_user_id, content)
    VALUES (?, ?, NULL, NULL, ?)
  `).run(articleId, req.user.id, content);

  res.status(201).json({ id: result.lastInsertRowid });
});

app.delete("/api/comments/:id", requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const comment = db.prepare("SELECT id, user_id, parent_id FROM comments WHERE id = ?").get(id);
  if (!comment) return res.status(404).json({ error: "Comment not found." });

  const isOwner = comment.user_id === req.user.id;
  const isAdmin = Boolean(req.user.is_admin);
  if (!isOwner && !isAdmin) return res.status(403).json({ error: "You can only delete your own comments." });

  // Every reply belongs to the same flat thread as its top-level comment.
  // Deleting any comment therefore removes the entire thread.
  const rootId = comment.parent_id || comment.id;
  db.prepare("DELETE FROM comments WHERE id = ? OR parent_id = ?").run(rootId, rootId);
  res.json({ ok: true, threadDeleted: true });
});

// Session state
app.get("/api/session", (req, res) => {
  const user = currentUser(req);
  res.json({
    loggedIn: Boolean(user),
    user: user ? {
      id: user.id,
      username: user.username,
      isAdmin: Boolean(user.is_admin)
    } : null
  });
});

// Basic in-memory login rate limiter. This protects the login endpoint
// without requiring another dependency. It resets when the server restarts.
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;

function loginRateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || "unknown";
  const entry = loginAttempts.get(key);

  if (!entry || now - entry.startedAt >= LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { startedAt: now, count: 0 });
    return next();
  }

  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((LOGIN_WINDOW_MS - (now - entry.startedAt)) / 1000);
    res.set("Retry-After", String(retryAfter));
    return res.status(429).json({ error: "Too many login attempts. Please try again later." });
  }

  next();
}

// Login
app.post("/api/login", loginRateLimit, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db.prepare(`
    SELECT id, username, password_hash, is_admin
    FROM users WHERE username = ? COLLATE NOCASE
  `).get(username);

  const valid = user ? await bcrypt.compare(password, user.password_hash) : false;

  if (!valid) {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const entry = loginAttempts.get(key);
    if (entry) entry.count += 1;
    return res.status(401).json({ error: "Username or password incorrect" });
  }

  // A successful login clears the failed-attempt counter for this IP.
  loginAttempts.delete(req.ip || req.socket.remoteAddress || "unknown");

  req.session.userId = user.id;
  res.json({
    username: user.username,
    isAdmin: Boolean(user.is_admin)
  });
});

app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// Admin: all articles
app.get("/api/admin/articles", requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, title, description, content, created_at, updated_at
    FROM articles ORDER BY datetime(updated_at) DESC, id DESC
  `).all();
  res.json(rows);
});

// Admin: create article
app.post("/api/admin/articles", requireAdmin, (req, res) => {
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  const content = String(req.body.content || "");

  if (!title) return res.status(400).json({ error: "Title is required." });

  const result = db.prepare(`
    INSERT INTO articles (title, description, content)
    VALUES (?, ?, ?)
  `).run(title, description, content);

  res.status(201).json({ id: result.lastInsertRowid });
});

// Admin: edit article
app.put("/api/admin/articles/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  const content = String(req.body.content || "");

  if (!title) return res.status(400).json({ error: "Title is required." });

  const result = db.prepare(`
    UPDATE articles
    SET title = ?, description = ?, content = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(title, description, content, id);

  if (!result.changes) return res.status(404).json({ error: "Article not found." });
  res.json({ ok: true });
});

// Admin: delete article
app.delete("/api/admin/articles/:id", requireAdmin, (req, res) => {
  const result = db.prepare("DELETE FROM articles WHERE id = ?")
    .run(Number(req.params.id));

  if (!result.changes) return res.status(404).json({ error: "Article not found." });
  res.json({ ok: true });
});

// Admin: list users
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, username, is_admin, created_at
    FROM users ORDER BY username COLLATE NOCASE
  `).all();

  res.json(rows.map(row => ({
    ...row,
    isAdmin: Boolean(row.is_admin)
  })));
});

// Admin: add user
app.post("/api/admin/users", requireAdmin, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  if (username.length > 50) {
    return res.status(400).json({ error: "Username is too long." });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }

  if (username.toLowerCase() === "daniel") {
    return res.status(400).json({ error: "Daniel is reserved for the administrator." });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, is_admin)
      VALUES (?, ?, 0)
    `).run(username, hash);

    res.status(201).json({ id: result.lastInsertRowid });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "That username already exists." });
    }
    throw error;
  }
});

// Admin: edit user
app.put("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare("SELECT id, username, is_admin FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "User not found." });

  const usernameProvided = Object.prototype.hasOwnProperty.call(req.body, "username");
  const passwordProvided = Object.prototype.hasOwnProperty.call(req.body, "password");
  const username = usernameProvided ? String(req.body.username || "").trim() : target.username;
  const password = passwordProvided ? String(req.body.password || "") : "";

  if (!username) return res.status(400).json({ error: "Username cannot be empty." });
  if (username.length > 50) return res.status(400).json({ error: "Username is too long." });
  if (target.is_admin && username.toLowerCase() !== "daniel") {
    return res.status(400).json({ error: "Daniel's administrator username cannot be changed." });
  }
  if (passwordProvided && password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }

  try {
    if (passwordProvided) {
      const hash = await bcrypt.hash(password, 12);
      db.prepare("UPDATE users SET username = ?, password_hash = ? WHERE id = ?").run(username, hash, id);
    } else {
      db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, id);
    }
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "That username already exists." });
    }
    throw error;
  }

  const selfChanged = id === req.session.userId;
  if (selfChanged) {
    const updated = db.prepare("SELECT id, username, is_admin FROM users WHERE id = ?").get(id);
    req.session.userId = updated.id;
  }

  const changes = [];
  if (usernameProvided && username !== target.username) changes.push("username");
  if (passwordProvided) changes.push("password");
  res.json({ ok: true, selfChanged, message: changes.length ? `Your ${changes.join(" and ")} changed.` : "No changes made." });
});

// Admin: delete user, but never Daniel/admin
app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare(
    "SELECT id, username, is_admin FROM users WHERE id = ?"
  ).get(id);

  if (!target) return res.status(404).json({ error: "User not found." });
  if (target.is_admin || target.username.toLowerCase() === "daniel") {
    return res.status(400).json({ error: "The Daniel administrator cannot be deleted." });
  }

  // Removing a user must also remove every thread that contains one of
  // that user's comments. Collect the thread roots before deleting anything.
  const threadRoots = db.prepare(`
    SELECT DISTINCT COALESCE(parent_id, id) AS root_id
    FROM comments
    WHERE user_id = ?
  `).all(id).map(row => row.root_id);

  const deleteUserAndThreads = db.transaction(() => {
    const deleteThread = db.prepare("DELETE FROM comments WHERE id = ? OR parent_id = ?");
    for (const rootId of threadRoots) {
      deleteThread.run(rootId, rootId);
    }
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
  });

  deleteUserAndThreads();
  res.json({ ok: true, threadsDeleted: threadRoots.length });
});

app.listen(port, () => {
  console.log(`Daniblog is running at http://localhost:${port}`);
});
