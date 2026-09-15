import "dotenv/config";
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { createClient } from "@libsql/client";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);

const port = Number(process.env.PORT || 3000);

if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error("TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required.");
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is required in .env");
  process.exit(1);
}

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

async function run(sql, args = []) {
  return db.execute({ sql, args });
}

async function rows(sql, args = []) {
  const result = await run(sql, args);
  return result.rows;
}

async function get(sql, args = []) {
  const result = await run(sql, args);
  return result.rows[0] ?? null;
}

function idFromResult(result) {
  return Number(result.lastInsertRowid);
}


/* =========================================================
   TURSO SESSION STORE
   Stores Express sessions in Turso instead of memory.
   This allows login sessions to survive Render redeploys.
   ========================================================= */

class TursoSessionStore extends session.Store {
  constructor(database) {
    super();
    this.database = database;
  }

  async get(sid, callback) {
    try {
      const result = await this.database.execute({
        sql: "SELECT sess, expires_at FROM sessions WHERE sid = ?",
        args: [sid]
      });

      const row = result.rows[0];

      if (!row) {
        return callback(null, null);
      }

      if (Number(row.expires_at) <= Date.now()) {
        await this.database.execute({
          sql: "DELETE FROM sessions WHERE sid = ?",
          args: [sid]
        });

        return callback(null, null);
      }

      let sess;

      try {
        sess = JSON.parse(String(row.sess));
      } catch {
        await this.database.execute({
          sql: "DELETE FROM sessions WHERE sid = ?",
          args: [sid]
        });

        return callback(null, null);
      }

      callback(null, sess);
    } catch (error) {
      callback(error);
    }
  }

  async set(sid, sess, callback) {
    try {
      const maxAge =
        sess?.cookie?.maxAge ??
        1000 * 60 * 60 * 24 * 7;

      const expiresAt = Date.now() + Number(maxAge);

      await this.database.execute({
        sql: `
          INSERT INTO sessions (sid, sess, expires_at)
          VALUES (?, ?, ?)
          ON CONFLICT(sid)
          DO UPDATE SET
            sess = excluded.sess,
            expires_at = excluded.expires_at
        `,
        args: [
          sid,
          JSON.stringify(sess),
          expiresAt
        ]
      });

      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  async destroy(sid, callback) {
    try {
      await this.database.execute({
        sql: "DELETE FROM sessions WHERE sid = ?",
        args: [sid]
      });

      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  async touch(sid, sess, callback) {
    try {
      const maxAge =
        sess?.cookie?.maxAge ??
        1000 * 60 * 60 * 24 * 7;

      const expiresAt = Date.now() + Number(maxAge);

      await this.database.execute({
        sql: `
          UPDATE sessions
          SET sess = ?, expires_at = ?
          WHERE sid = ?
        `,
        args: [
          JSON.stringify(sess),
          expiresAt,
          sid
        ]
      });

      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }
}


/* =========================================================
   DATABASE INITIALIZATION
   ========================================================= */

async function initializeDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      can_post INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL DEFAULT '',
      author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      status TEXT NOT NULL DEFAULT 'published',
      review_note TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await run(`
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
  `);

  /* =======================================================
     PERSISTENT LOGIN SESSIONS
     ======================================================= */

  await run(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);

  await run(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
  `);

  const userColumns = (await rows("PRAGMA table_info(users)"))
    .map(r => r.name);

  if (!userColumns.includes("can_post")) {
    await run(
      "ALTER TABLE users ADD COLUMN can_post INTEGER NOT NULL DEFAULT 0"
    );
  }

  const commentColumns = (await rows("PRAGMA table_info(comments)"))
    .map(r => r.name);

  if (!commentColumns.includes("parent_id")) {
    await run(
      "ALTER TABLE comments ADD COLUMN parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE"
    );
  }

  if (!commentColumns.includes("reply_to_user_id")) {
    await run(
      "ALTER TABLE comments ADD COLUMN reply_to_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
    );
  }

  await run(
    "CREATE INDEX IF NOT EXISTS idx_comments_article_parent ON comments(article_id, parent_id, id)"
  );

  const articleColumns = (await rows("PRAGMA table_info(articles)"))
    .map(r => r.name);

  if (!articleColumns.includes("author_id")) {
    await run(
      "ALTER TABLE articles ADD COLUMN author_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
    );
  }

  if (!articleColumns.includes("status")) {
    await run(
      "ALTER TABLE articles ADD COLUMN status TEXT NOT NULL DEFAULT 'published'"
    );
  }

  if (!articleColumns.includes("review_note")) {
    await run(
      "ALTER TABLE articles ADD COLUMN review_note TEXT NOT NULL DEFAULT ''"
    );
  }

  await run(
    "CREATE INDEX IF NOT EXISTS idx_articles_status_created ON articles(status, created_at)"
  );

  const danielUser = await get(
    "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
    ["Daniel"]
  );

  if (danielUser) {
    await run(
      "UPDATE articles SET author_id = ? WHERE author_id IS NULL",
      [danielUser.id]
    );
  }

  if (process.env.ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

    const existing = await get(
      "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
      ["Daniel"]
    );

    if (existing) {
      await run(
        "UPDATE users SET password_hash = ?, is_admin = 1, can_post = 1 WHERE id = ?",
        [hash, existing.id]
      );

      console.log("Daniel administrator account verified.");
    } else {
      await run(
        "INSERT INTO users (username, password_hash, is_admin, can_post) VALUES (?, ?, 1, 1)",
        ["Daniel", hash]
      );

      console.log("Daniel administrator account created.");
    }
  } else {
    console.warn(
      "ADMIN_PASSWORD is not set; Daniel's admin account was not created or updated."
    );
  }
}


/* =========================================================
   EXPRESS MIDDLEWARE
   ========================================================= */

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

const sessionStore = new TursoSessionStore(db);

app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));


/* =========================================================
   USER AUTHORIZATION HELPERS
   ========================================================= */

async function currentUser(req) {
  if (!req.session.userId) return null;

  return get(
    "SELECT id, username, is_admin, can_post FROM users WHERE id = ?",
    [req.session.userId]
  );
}

async function requireLogin(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Not logged in."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user?.is_admin) {
      return res.status(403).json({
        error: "Admin access required."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function requirePostPermission(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Not logged in."
      });
    }

    if (!user.is_admin && !user.can_post) {
      return res.status(403).json({
        error: "You do not have permission to create posts."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}


/* =========================================================
   PUBLIC ARTICLES
   ========================================================= */

app.get("/api/articles", async (req, res, next) => {
  try {
    const result = await rows(`
      SELECT
        a.id,
        a.title,
        a.description,
        a.content,
        a.created_at,
        a.updated_at,
        a.author_id,
        u.username AS author_username,
        (
          SELECT COUNT(*)
          FROM comments c
          WHERE c.article_id = a.id
        ) AS comment_count
      FROM articles a
      LEFT JOIN users u ON u.id = a.author_id
      WHERE a.status = 'published'
      ORDER BY datetime(a.created_at) DESC, a.id DESC
    `);

    res.json(result);
  } catch (e) {
    next(e);
  }
});


app.get("/api/articles/:id", async (req, res, next) => {
  try {
    const row = await get(`
      SELECT
        a.id,
        a.title,
        a.description,
        a.content,
        a.created_at,
        a.updated_at,
        a.author_id,
        u.username AS author_username
      FROM articles a
      LEFT JOIN users u ON u.id = a.author_id
      WHERE a.id = ? AND a.status = 'published'
    `, [Number(req.params.id)]);

    if (!row) {
      return res.status(404).json({
        error: "Article not found."
      });
    }

    res.json(row);
  } catch (e) {
    next(e);
  }
});


/* =========================================================
   COMMENTS
   ========================================================= */

app.get("/api/articles/:id/comments", async (req, res, next) => {
  try {
    const articleId = Number(req.params.id);

    const article = await get(
      "SELECT id FROM articles WHERE id = ? AND status = 'published'",
      [articleId]
    );

    if (!article) {
      return res.status(404).json({
        error: "Article not found."
      });
    }

    const result = await rows(`
      SELECT
        c.id,
        c.article_id,
        c.user_id,
        c.parent_id,
        c.content,
        c.created_at,
        u.username,
        reply_user.username AS reply_to_username
      FROM comments c
      JOIN users u ON u.id = c.user_id
      LEFT JOIN users reply_user
        ON reply_user.id = c.reply_to_user_id
      WHERE c.article_id = ?
      ORDER BY datetime(c.created_at) ASC, c.id ASC
    `, [articleId]);

    res.json(result);
  } catch (e) {
    next(e);
  }
});


app.post(
  "/api/articles/:id/comments",
  requireLogin,
  async (req, res, next) => {
    try {
      const articleId = Number(req.params.id);
      const content = String(req.body.content || "").trim();

      const parentId =
        req.body.parentId == null || req.body.parentId === ""
          ? null
          : Number(req.body.parentId);

      const replyToUserId =
        req.body.replyToUserId == null ||
        req.body.replyToUserId === ""
          ? null
          : Number(req.body.replyToUserId);

      const article = await get(
        "SELECT id FROM articles WHERE id = ? AND status = 'published'",
        [articleId]
      );

      if (!article) {
        return res.status(404).json({
          error: "Article not found."
        });
      }

      if (!content) {
        return res.status(400).json({
          error: "Comment cannot be empty."
        });
      }

      if (content.length > 5000) {
        return res.status(400).json({
          error: "Comment is too long."
        });
      }

      if (parentId !== null) {
        const parent = await get(
          "SELECT id, article_id, parent_id FROM comments WHERE id = ?",
          [parentId]
        );

        if (
          !parent ||
          Number(parent.article_id) !== articleId
        ) {
          return res.status(400).json({
            error: "Reply target not found."
          });
        }

        const rootId = parent.parent_id || parent.id;

        if (replyToUserId !== null) {
          const replyUser = await get(
            "SELECT id FROM users WHERE id = ?",
            [replyToUserId]
          );

          if (!replyUser) {
            return res.status(400).json({
              error: "Reply user not found."
            });
          }
        }

        const result = await run(
          `
          INSERT INTO comments
            (article_id, user_id, parent_id, reply_to_user_id, content)
          VALUES (?, ?, ?, ?, ?)
          `,
          [
            articleId,
            req.user.id,
            rootId,
            replyToUserId,
            content
          ]
        );

        return res.status(201).json({
          id: idFromResult(result)
        });
      }

      const result = await run(
        `
        INSERT INTO comments
          (article_id, user_id, parent_id, reply_to_user_id, content)
        VALUES (?, ?, NULL, NULL, ?)
        `,
        [
          articleId,
          req.user.id,
          content
        ]
      );

      res.status(201).json({
        id: idFromResult(result)
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   DELETE COMMENT THREAD
   ========================================================= */

app.delete(
  "/api/comments/:id",
  requireLogin,
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);

      const comment = await get(
        "SELECT id, user_id, parent_id FROM comments WHERE id = ?",
        [id]
      );

      if (!comment) {
        return res.status(404).json({
          error: "Comment not found."
        });
      }

      if (
        Number(comment.user_id) !== Number(req.user.id) &&
        !req.user.is_admin
      ) {
        return res.status(403).json({
          error: "You can only delete your own comments."
        });
      }

      const rootId = comment.parent_id || comment.id;

      await run(
        "DELETE FROM comments WHERE id = ? OR parent_id = ?",
        [rootId, rootId]
      );

      res.json({
        ok: true,
        threadDeleted: true
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   SESSION
   ========================================================= */

app.get("/api/session", async (req, res, next) => {
  try {
    const user = await currentUser(req);

    res.json({
      loggedIn: Boolean(user),
      user: user
        ? {
            id: user.id,
            username: user.username,
            isAdmin: Boolean(user.is_admin),
            canPost: Boolean(user.can_post)
          }
        : null
    });
  } catch (e) {
    next(e);
  }
});


/* =========================================================
   LOGIN RATE LIMIT
   ========================================================= */

const loginAttempts = new Map();

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;

function loginRateLimit(req, res, next) {
  const now = Date.now();

  const key =
    req.ip ||
    req.socket.remoteAddress ||
    "unknown";

  const entry = loginAttempts.get(key);

  if (
    !entry ||
    now - entry.startedAt >= LOGIN_WINDOW_MS
  ) {
    loginAttempts.set(key, {
      startedAt: now,
      count: 0
    });

    return next();
  }

  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    const retryAfter = Math.ceil(
      (LOGIN_WINDOW_MS - (now - entry.startedAt)) / 1000
    );

    res.set(
      "Retry-After",
      String(retryAfter)
    );

    return res.status(429).json({
      error:
        "Too many login attempts. Please try again later."
    });
  }

  next();
}


/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/login",
  loginRateLimit,
  async (req, res, next) => {
    try {
      const username =
        String(req.body.username || "").trim();

      const password =
        String(req.body.password || "");

      const user = await get(
        `
        SELECT
          id,
          username,
          password_hash,
          is_admin,
          can_post
        FROM users
        WHERE username = ? COLLATE NOCASE
        `,
        [username]
      );

      const valid = user
        ? await bcrypt.compare(
            password,
            user.password_hash
          )
        : false;

      if (!valid) {
        const key =
          req.ip ||
          req.socket.remoteAddress ||
          "unknown";

        const entry = loginAttempts.get(key);

        if (entry) {
          entry.count += 1;
        }

        return res.status(401).json({
          error:
            "Username or password incorrect"
        });
      }

      loginAttempts.delete(
        req.ip ||
        req.socket.remoteAddress ||
        "unknown"
      );

      req.session.userId = user.id;

      res.json({
        username: user.username,
        isAdmin: Boolean(user.is_admin)
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/logout",
  requireLogin,
  (req, res, next) => {
    req.session.destroy(err => {
      if (err) return next(err);

      res.json({
        ok: true
      });
    });
  }
);


/* =========================================================
   ADMIN ARTICLES
   ========================================================= */

app.get(
  "/api/admin/articles/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const row = await get(
        `
        SELECT
          a.id,
          a.title,
          a.description,
          a.content,
          a.created_at,
          a.updated_at,
          a.author_id,
          u.username AS author_username,
          a.status,
          a.review_note
        FROM articles a
        LEFT JOIN users u
          ON u.id = a.author_id
        WHERE a.id = ?
        `,
        [Number(req.params.id)]
      );

      if (!row) {
        return res.status(404).json({
          error: "Article not found."
        });
      }

      res.json(row);
    } catch (e) {
      next(e);
    }
  }
);


app.get(
  "/api/admin/articles",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await rows(
        `
        SELECT
          a.id,
          a.title,
          a.description,
          a.content,
          a.created_at,
          a.updated_at,
          a.author_id,
          u.username AS author_username,
          a.status,
          a.review_note
        FROM articles a
        LEFT JOIN users u
          ON u.id = a.author_id
        ORDER BY
          CASE a.status
            WHEN 'pending' THEN 0
            WHEN 'published' THEN 1
            ELSE 2
          END,
          datetime(a.updated_at) DESC,
          a.id DESC
        `
      );

      res.json(result);
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN CREATE ARTICLE
   ========================================================= */

app.post(
  "/api/admin/articles",
  requireAdmin,
  async (req, res, next) => {
    try {
      const title =
        String(req.body.title || "").trim();

      const description =
        String(req.body.description || "").trim();

      const content =
        String(req.body.content || "");

      if (!title) {
        return res.status(400).json({
          error: "Title is required."
        });
      }

      const result = await run(
        `
        INSERT INTO articles
          (
            title,
            description,
            content,
            author_id,
            status,
            review_note
          )
        VALUES (?, ?, ?, ?, 'published', '')
        `,
        [
          title,
          description,
          content,
          req.user.id
        ]
      );

      res.status(201).json({
        id: idFromResult(result),
        status: "published"
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   USER CREATE ARTICLE
   ========================================================= */

app.post(
  "/api/articles",
  requirePostPermission,
  async (req, res, next) => {
    try {
      const title =
        String(req.body.title || "").trim();

      const description =
        String(req.body.description || "").trim();

      const content =
        String(req.body.content || "");

      if (!title) {
        return res.status(400).json({
          error: "Title is required."
        });
      }

      if (!content.trim()) {
        return res.status(400).json({
          error: "Content is required."
        });
      }

      const result = await run(
        `
        INSERT INTO articles
          (
            title,
            description,
            content,
            author_id,
            status,
            review_note
          )
        VALUES (?, ?, ?, ?, 'pending', '')
        `,
        [
          title,
          description,
          content,
          req.user.id
        ]
      );

      res.status(201).json({
        id: idFromResult(result),
        status: "pending"
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN EDIT ARTICLE
   ========================================================= */

app.put(
  "/api/admin/articles/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const id =
        Number(req.params.id);

      const title =
        String(req.body.title || "").trim();

      const description =
        String(req.body.description || "").trim();

      const content =
        String(req.body.content || "");

      if (!title) {
        return res.status(400).json({
          error: "Title is required."
        });
      }

      const result = await run(
        `
        UPDATE articles
        SET
          title = ?,
          description = ?,
          content = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [
          title,
          description,
          content,
          id
        ]
      );

      if (!Number(result.rowsAffected)) {
        return res.status(404).json({
          error: "Article not found."
        });
      }

      res.json({
        ok: true
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN APPROVE / DENY ARTICLE
   ========================================================= */

app.post(
  "/api/admin/articles/:id/review",
  requireAdmin,
  async (req, res, next) => {
    try {
      const id =
        Number(req.params.id);

      const decision =
        String(req.body.decision || "").toLowerCase();

      const note =
        String(req.body.note || "")
          .trim()
          .slice(0, 1000);

      if (
        !["approve", "deny"].includes(decision)
      ) {
        return res.status(400).json({
          error:
            "Decision must be approve or deny."
        });
      }

      const status =
        decision === "approve"
          ? "published"
          : "denied";

      const result = await run(
        `
        UPDATE articles
        SET
          status = ?,
          review_note = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [
          status,
          note,
          id
        ]
      );

      if (!Number(result.rowsAffected)) {
        return res.status(404).json({
          error: "Article not found."
        });
      }

      res.json({
        ok: true,
        status
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN DELETE ARTICLE
   ========================================================= */

app.delete(
  "/api/admin/articles/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await run(
        "DELETE FROM articles WHERE id = ?",
        [Number(req.params.id)]
      );

      if (!Number(result.rowsAffected)) {
        return res.status(404).json({
          error: "Article not found."
        });
      }

      res.json({
        ok: true
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN USERS
   ========================================================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await rows(
        `
        SELECT
          id,
          username,
          is_admin,
          can_post,
          created_at
        FROM users
        ORDER BY username COLLATE NOCASE
        `
      );

      res.json(
        result.map(row => ({
          ...row,
          isAdmin: Boolean(row.is_admin),
          canPost: Boolean(row.can_post)
        }))
      );
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN CREATE USER
   ========================================================= */

app.post(
  "/api/admin/users",
  requireAdmin,
  async (req, res, next) => {
    try {
      const username =
        String(req.body.username || "").trim();

      const password =
        String(req.body.password || "");

      if (!username || !password) {
        return res.status(400).json({
          error:
            "Username and password are required."
        });
      }

      if (username.length > 50) {
        return res.status(400).json({
          error: "Username is too long."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters."
        });
      }

      if (
        username.toLowerCase() === "daniel"
      ) {
        return res.status(400).json({
          error:
            "Daniel is reserved for the administrator."
        });
      }

      const hash =
        await bcrypt.hash(password, 12);

      try {
        const result = await run(
          `
          INSERT INTO users
            (
              username,
              password_hash,
              is_admin,
              can_post
            )
          VALUES (?, ?, 0, 0)
          `,
          [
            username,
            hash
          ]
        );

        res.status(201).json({
          id: idFromResult(result)
        });
      } catch (error) {
        if (
          String(error.message)
            .toLowerCase()
            .includes("unique")
        ) {
          return res.status(409).json({
            error:
              "That username already exists."
          });
        }

        throw error;
      }
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN EDIT USER
   ========================================================= */

app.put(
  "/api/admin/users/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const id =
        Number(req.params.id);

      const target = await get(
        `
        SELECT
          id,
          username,
          is_admin,
          can_post
        FROM users
        WHERE id = ?
        `,
        [id]
      );

      if (!target) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      const usernameProvided =
        Object.prototype.hasOwnProperty.call(
          req.body,
          "username"
        );

      const passwordProvided =
        Object.prototype.hasOwnProperty.call(
          req.body,
          "password"
        );

      const username =
        usernameProvided
          ? String(req.body.username || "").trim()
          : target.username;

      const password =
        passwordProvided
          ? String(req.body.password || "")
          : "";

      const canPost =
        Object.prototype.hasOwnProperty.call(
          req.body,
          "canPost"
        )
          ? Boolean(req.body.canPost)
          : Boolean(target.can_post);

      if (!username) {
        return res.status(400).json({
          error:
            "Username cannot be empty."
        });
      }

      if (username.length > 50) {
        return res.status(400).json({
          error:
            "Username is too long."
        });
      }

      if (
        target.is_admin &&
        username.toLowerCase() !== "daniel"
      ) {
        return res.status(400).json({
          error:
            "Daniel's administrator username cannot be changed."
        });
      }

      if (
        passwordProvided &&
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters."
        });
      }

      try {
        if (passwordProvided) {
          const hash =
            await bcrypt.hash(password, 12);

          await run(
            `
            UPDATE users
            SET
              username = ?,
              password_hash = ?,
              can_post = ?
            WHERE id = ?
            `,
            [
              username,
              hash,
              canPost ? 1 : 0,
              id
            ]
          );
        } else {
          await run(
            `
            UPDATE users
            SET
              username = ?,
              can_post = ?
            WHERE id = ?
            `,
            [
              username,
              canPost ? 1 : 0,
              id
            ]
          );
        }
      } catch (error) {
        if (
          String(error.message)
            .toLowerCase()
            .includes("unique")
        ) {
          return res.status(409).json({
            error:
              "That username already exists."
          });
        }

        throw error;
      }

      const selfChanged =
        id === Number(req.session.userId);

      const changes = [];

      if (
        usernameProvided &&
        username !== target.username
      ) {
        changes.push("username");
      }

      if (passwordProvided) {
        changes.push("password");
      }

      res.json({
        ok: true,
        selfChanged,
        message:
          changes.length
            ? `Your ${changes.join(" and ")} changed.`
            : "No changes made."
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ADMIN DELETE USER
   ========================================================= */

app.delete(
  "/api/admin/users/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const id =
        Number(req.params.id);

      const target = await get(
        `
        SELECT
          id,
          username,
          is_admin,
          can_post
        FROM users
        WHERE id = ?
        `,
        [id]
      );

      if (!target) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      if (
        target.is_admin ||
        String(target.username).toLowerCase() ===
          "daniel"
      ) {
        return res.status(400).json({
          error:
            "The Daniel administrator cannot be deleted."
        });
      }

      const threadRows = await rows(
        `
        SELECT DISTINCT
          COALESCE(parent_id, id) AS root_id
        FROM comments
        WHERE user_id = ?
        `,
        [id]
      );

      for (const row of threadRows) {
        await run(
          "DELETE FROM comments WHERE id = ? OR parent_id = ?",
          [
            row.root_id,
            row.root_id
          ]
        );
      }

      await run(
        "DELETE FROM users WHERE id = ?",
        [id]
      );

      res.json({
        ok: true,
        threadsDeleted:
          threadRows.length
      });
    } catch (e) {
      next(e);
    }
  }
);


/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Server error."
  });
});


/* =========================================================
   START SERVER
   ========================================================= */

await initializeDatabase();

app.listen(
  port,
  () =>
    console.log(
      `Daniblog is running on port ${port}`
    )
);
