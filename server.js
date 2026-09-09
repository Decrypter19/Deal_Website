"use strict";
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { createClient } = require("@libsql/client");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "deal.sqlite");
const OFFICER_EMAILS = (process.env.OFFICER_EMAILS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const SCHOOL_DOMAINS = (process.env.SCHOOL_DOMAINS || "brophybroncos.org,xaviersaints.org,.edu,k12.")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const SESSION_DAYS = 30;

// TURSO_DATABASE_URL (libsql://...) + TURSO_AUTH_TOKEN use hosted Turso; otherwise a local file.
if (!process.env.TURSO_DATABASE_URL) require("fs").mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = createClient(process.env.TURSO_DATABASE_URL
  ? { url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN }
  : { url: "file:" + DB_PATH });
const get = async (sql, args = []) => (await db.execute({ sql, args })).rows[0];
const all = async (sql, args = []) => (await db.execute({ sql, args })).rows;
const run = (sql, args = []) => db.execute({ sql, args });
const SCHEMA = `
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  school TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','officer')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  user_agent TEXT
);
CREATE TABLE IF NOT EXISTS login_events (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  member_id INTEGER,
  ok INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS password_resets (
  token TEXT PRIMARY KEY,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  what TEXT NOT NULL,
  assigned_to INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  created_by INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  due TEXT,
  done INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  from_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  to_id INTEGER REFERENCES members(id) ON DELETE CASCADE, -- NULL = everyone
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS message_reads (
  message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  read_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (message_id, member_id)
);
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY,
  by_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());

/* ---------- helpers ---------- */
const isEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const isSchoolEmail = e => isEmail(e) && SCHOOL_DOMAINS.some(d => e.endsWith(d) || e.includes(d));
const publicMember = m => ({ id: m.id, name: m.name, email: m.email, school: m.school, role: m.role,
  created_at: m.created_at, last_login_at: m.last_login_at });
const bad = (res, code, error) => res.status(code).json({ error });

async function createSession(res, member, req) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
  await run("INSERT INTO sessions(token,member_id,expires_at,user_agent) VALUES(?,?,?,?)", [token, member.id, expires.toISOString(), req.get("user-agent") || ""]);
  res.cookie("deal_session", token, {
    httpOnly: true, sameSite: "lax", secure: req.secure || process.env.NODE_ENV === "production", expires, path: "/"
  });
}
async function auth(req, res, next) {
  const token = req.cookies.deal_session;
  if (!token) return bad(res, 401, "Not signed in.");
  const row = await get(`SELECT m.* FROM sessions s JOIN members m ON m.id=s.member_id
    WHERE s.token=? AND s.expires_at>datetime('now')`, [token]);
  if (!row) { res.clearCookie("deal_session"); return bad(res, 401, "Session expired. Sign in again."); }
  req.user = row;
  next();
}
const officerOnly = (req, res, next) => req.user.role === "officer" ? next() : bad(res, 403, "Officers only.");

/* ---------- auth ---------- */
app.post("/api/auth/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const school = String(req.body.school || "").trim();
  const password = String(req.body.password || "");
  if (!name) return bad(res, 400, "Enter your full name.");
  if (!isSchoolEmail(email)) return bad(res, 400, "Use your school email address, not a personal one.");
  if (!school) return bad(res, 400, "Enter your school.");
  if (password.length < 8) return bad(res, 400, "Choose a password of at least 8 characters.");
  if (await get("SELECT 1 FROM members WHERE email=?", [email])) return bad(res, 409, "An account with that email already exists.");
  const count = Number((await get("SELECT COUNT(*) c FROM members")).c);
  const role = (count === 0 || OFFICER_EMAILS.includes(email)) ? "officer" : "member";
  const hash = await bcrypt.hash(password, 11);
  const info = await run("INSERT INTO members(name,email,school,password_hash,role,last_login_at) VALUES(?,?,?,?,?,datetime('now'))", [name, email, school, hash, role]);
  const member = await get("SELECT * FROM members WHERE id=?", [Number(info.lastInsertRowid)]);
  await run("INSERT INTO login_events(email,member_id,ok,ip,user_agent) VALUES(?,?,1,?,?)", [email, member.id, req.ip, req.get("user-agent") || ""]);
  await createSession(res, member, req);
  res.status(201).json({ member: publicMember(member) });
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const member = await get("SELECT * FROM members WHERE email=?", [email]);
  const ok = member && await bcrypt.compare(password, member.password_hash);
  await run("INSERT INTO login_events(email,member_id,ok,ip,user_agent) VALUES(?,?,?,?,?)", [email, member ? member.id : null, ok ? 1 : 0, req.ip, req.get("user-agent") || ""]);
  if (!ok) return bad(res, 401, "Incorrect email or password.");
  await run("UPDATE members SET last_login_at=datetime('now') WHERE id=?", [member.id]);
  await createSession(res, member, req);
  res.json({ member: publicMember(member) });
});

app.post("/api/auth/logout", async (req, res) => {
  if (req.cookies.deal_session) await run("DELETE FROM sessions WHERE token=?", [req.cookies.deal_session]);
  res.clearCookie("deal_session");
  res.json({ ok: true });
});

app.get("/api/auth/me", auth, async (req, res) => res.json({ member: publicMember(req.user) }));

app.patch("/api/auth/me", auth, async (req, res) => {
  const name = String(req.body.name || "").trim(), school = String(req.body.school || "").trim();
  if (!name) return bad(res, 400, "Name is required.");
  await run("UPDATE members SET name=?,school=? WHERE id=?", [name, school, req.user.id]);
  res.json({ member: publicMember(await get("SELECT * FROM members WHERE id=?", [req.user.id])) });
});

app.post("/api/auth/change-password", auth, async (req, res) => {
  const cur = String(req.body.current || ""), next = String(req.body.next || "");
  if (!(await bcrypt.compare(cur, req.user.password_hash))) return bad(res, 401, "Current password is incorrect.");
  if (next.length < 8) return bad(res, 400, "New password must be at least 8 characters.");
  await run("UPDATE members SET password_hash=? WHERE id=?", [await bcrypt.hash(next, 11), req.user.id]);
  res.json({ ok: true });
});

// No email provider is configured, so resets work by an officer generating a link
// for the member (POST /api/members/:id/reset-link) and sharing it directly.
app.post("/api/auth/forgot", async (req, res) => {
  res.json({ ok: true, message: "Ask a DEAL officer for a password reset link. They can generate one from the Members page." });
});
app.post("/api/auth/reset", async (req, res) => {
  const token = String(req.body.token || ""), password = String(req.body.password || "");
  const row = await get("SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at>datetime('now')", [token]);
  if (!row) return bad(res, 400, "This reset link is invalid or has expired.");
  if (password.length < 8) return bad(res, 400, "Choose a password of at least 8 characters.");
  await run("UPDATE members SET password_hash=? WHERE id=?", [await bcrypt.hash(password, 11), row.member_id]);
  await run("UPDATE password_resets SET used=1 WHERE token=?", [token]);
  await run("DELETE FROM sessions WHERE member_id=?", [row.member_id]);
  res.json({ ok: true });
});

/* ---------- members ---------- */
app.get("/api/members", auth, async (req, res) => {
  const rows = await all("SELECT * FROM members ORDER BY role DESC, name");
  res.json({ members: rows.map(m => req.user.role === "officer" ? publicMember(m)
    : { id: m.id, name: m.name, role: m.role, school: m.school }) });
});
app.get("/api/members/logins", auth, officerOnly, async (req, res) => {
  res.json({ events: await all("SELECT * FROM login_events ORDER BY at DESC LIMIT 200") });
});
app.patch("/api/members/:id", auth, officerOnly, async (req, res) => {
  const role = req.body.role;
  if (!["member", "officer"].includes(role)) return bad(res, 400, "Role must be member or officer.");
  if (+req.params.id === req.user.id && role !== "officer") return bad(res, 400, "You cannot remove your own officer role.");
  await run("UPDATE members SET role=? WHERE id=?", [role, req.params.id]);
  res.json({ ok: true });
});
app.delete("/api/members/:id", auth, officerOnly, async (req, res) => {
  if (+req.params.id === req.user.id) return bad(res, 400, "You cannot delete yourself.");
  await run("DELETE FROM members WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});
app.post("/api/members/:id/reset-link", auth, officerOnly, async (req, res) => {
  const m = await get("SELECT id FROM members WHERE id=?", [req.params.id]);
  if (!m) return bad(res, 404, "No such member.");
  const token = crypto.randomBytes(24).toString("hex");
  await run("INSERT INTO password_resets(token,member_id,expires_at) VALUES(?,?,?)", [token, m.id, new Date(Date.now() + 2 * 3600e3).toISOString()]);
  res.json({ url: `${req.protocol}://${req.get("host")}/#/portal/reset/${token}`, expires_in: "2 hours" });
});

/* ---------- tasks ---------- */
const TASK_SQL = `SELECT t.*, a.name AS who, c.name AS by FROM tasks t
  JOIN members a ON a.id=t.assigned_to JOIN members c ON c.id=t.created_by`;
app.get("/api/tasks", auth, async (req, res) => {
  const rows = req.query.scope === "all"
    ? await all(TASK_SQL + " ORDER BY t.done, t.created_at DESC")
    : await all(TASK_SQL + " WHERE t.assigned_to=? ORDER BY t.done, t.created_at DESC", [req.user.id]);
  res.json({ tasks: rows });
});
app.post("/api/tasks", auth, async (req, res) => {
  const what = String(req.body.what || "").trim(), due = String(req.body.due || "").trim() || null;
  const to = +req.body.assigned_to;
  if (!what) return bad(res, 400, "Describe the task.");
  if (!await get("SELECT 1 FROM members WHERE id=?", [to])) return bad(res, 400, "Choose who the task is for.");
  const info = await run("INSERT INTO tasks(what,assigned_to,created_by,due) VALUES(?,?,?,?)", [what, to, req.user.id, due]);
  res.status(201).json({ task: await get(TASK_SQL + " WHERE t.id=?", [Number(info.lastInsertRowid)]) });
});
app.patch("/api/tasks/:id", auth, async (req, res) => {
  const t = await get("SELECT * FROM tasks WHERE id=?", [req.params.id]);
  if (!t) return bad(res, 404, "No such task.");
  if (t.assigned_to !== req.user.id && t.created_by !== req.user.id && req.user.role !== "officer") return bad(res, 403, "Not your task.");
  await run("UPDATE tasks SET done=? WHERE id=?", [req.body.done ? 1 : 0, t.id]);
  res.json({ task: await get(TASK_SQL + " WHERE t.id=?", [t.id]) });
});
app.delete("/api/tasks/:id", auth, async (req, res) => {
  const t = await get("SELECT * FROM tasks WHERE id=?", [req.params.id]);
  if (!t) return bad(res, 404, "No such task.");
  if (t.created_by !== req.user.id && req.user.role !== "officer") return bad(res, 403, "Only the creator or an officer can delete this.");
  await run("DELETE FROM tasks WHERE id=?", [t.id]);
  res.json({ ok: true });
});

/* ---------- messages ---------- */
const MSG_SQL = `SELECT m.*, f.name AS from_name, f.role AS from_role, t.name AS to_name,
  EXISTS(SELECT 1 FROM message_reads r WHERE r.message_id=m.id AND r.member_id=?) AS read
  FROM messages m JOIN members f ON f.id=m.from_id LEFT JOIN members t ON t.id=m.to_id`;
app.get("/api/messages", auth, async (req, res) => {
  const inbox = await all(MSG_SQL + " WHERE (m.to_id=? OR m.to_id IS NULL) AND m.from_id<>? ORDER BY m.created_at DESC LIMIT 200", [req.user.id, req.user.id, req.user.id]);
  const sent = await all(MSG_SQL + " WHERE m.from_id=? ORDER BY m.created_at DESC LIMIT 200", [req.user.id, req.user.id]);
  res.json({ inbox, sent, unread: inbox.filter(m => !m.read).length });
});
app.post("/api/messages", auth, async (req, res) => {
  const body = String(req.body.body || "").trim();
  if (!body) return bad(res, 400, "Write a message.");
  let to = req.body.to_id === "all" || req.body.to_id === null ? null : +req.body.to_id;
  if (to === null) {
    if (req.user.role !== "officer") return bad(res, 403, "Only officers can message everyone.");
  } else {
    const target = await get("SELECT * FROM members WHERE id=?", [to]);
    if (!target) return bad(res, 400, "Choose a recipient.");
    if (req.user.role !== "officer" && target.role !== "officer") return bad(res, 403, "Members can message officers; officers can message anyone.");
  }
  const info = await run("INSERT INTO messages(from_id,to_id,body) VALUES(?,?,?)", [req.user.id, to, body]);
  res.status(201).json({ message: await get(MSG_SQL + " WHERE m.id=?", [req.user.id, Number(info.lastInsertRowid)]) });
});
app.post("/api/messages/:id/read", auth, async (req, res) => {
  await run("INSERT OR IGNORE INTO message_reads(message_id,member_id) VALUES(?,?)", [req.params.id, req.user.id]);
  res.json({ ok: true });
});

/* ---------- announcements ---------- */
const ANN_SQL = "SELECT a.*, m.name AS by FROM announcements a JOIN members m ON m.id=a.by_id";
app.get("/api/announcements", auth, async (req, res) =>
  res.json({ announcements: await all(ANN_SQL + " ORDER BY a.created_at DESC LIMIT 100") }));
app.post("/api/announcements", auth, async (req, res) => {
  const title = String(req.body.title || "").trim(), body = String(req.body.body || "").trim();
  if (!title || !body) return bad(res, 400, "Add a title and a message.");
  const info = await run("INSERT INTO announcements(by_id,title,body) VALUES(?,?,?)", [req.user.id, title, body]);
  res.status(201).json({ announcement: await get(ANN_SQL + " WHERE a.id=?", [Number(info.lastInsertRowid)]) });
});
app.delete("/api/announcements/:id", auth, async (req, res) => {
  const a = await get("SELECT * FROM announcements WHERE id=?", [req.params.id]);
  if (!a) return bad(res, 404, "No such announcement.");
  if (a.by_id !== req.user.id && req.user.role !== "officer") return bad(res, 403, "Not yours.");
  await run("DELETE FROM announcements WHERE id=?", [a.id]);
  res.json({ ok: true });
});

/* ---------- static site ---------- */
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.use("/api", (req, res) => bad(res, 404, "Not found."));
app.use((err, req, res, next) => { console.error(err); bad(res, 500, "Something went wrong."); });

setInterval(() => run("DELETE FROM sessions WHERE expires_at<=datetime('now')").catch(console.error), 3600e3).unref();

db.executeMultiple("PRAGMA foreign_keys = ON;" + SCHEMA)
  .then(() => app.listen(PORT, () => console.log(`DEAL portal running on http://localhost:${PORT}`)))
  .catch(e => { console.error("Database setup failed:", e); process.exit(1); });
