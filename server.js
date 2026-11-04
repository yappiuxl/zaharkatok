import express from 'express';
import multer from 'multer';
import { WebSocketServer } from 'ws';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });

// ===================== DB =====================
const db = new Database(path.join(DATA_DIR, 'data.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    nick TEXT NOT NULL,
    avatar TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    author_id TEXT NOT NULL,
    author TEXT NOT NULL,
    text TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    media_url TEXT,
    mime_type TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS likes (
    post_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (post_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    post_id TEXT NOT NULL,
    author_id TEXT NOT NULL,
    author TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
  CREATE INDEX IF NOT EXISTS idx_likes_post ON likes(post_id);
`);

// ===================== AUTH =====================
function newId(prefix) {
  return prefix + '_' + crypto.randomBytes(8).toString('hex');
}

function createSession(nick, avatar) {
  nick = String(nick || '').trim().slice(0, 20);
  if (nick.length < 2) throw new Error('nick_too_short');
  let user = db.prepare('SELECT * FROM users WHERE nick = ?').get(nick);
  const now = Date.now();
  if (!user) {
    user = { id: newId('u'), nick, avatar: avatar || null, created_at: now };
    db.prepare('INSERT INTO users (id, nick, avatar, created_at) VALUES (?,?,?,?)')
      .run(user.id, user.nick, user.avatar, user.created_at);
  } else if (avatar !== undefined && avatar !== null) {
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar, user.id);
    user.avatar = avatar;
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)')
    .run(token, user.id, now);
  return { user, token };
}

function authFromToken(token) {
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ?
  `).get(token);
  return row || null;
}

function authMiddleware(req, res, next) {
  const token = req.headers['x-token'] || req.query.token;
  const user = authFromToken(token);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  req.user = user;
  next();
}

// ===================== UPLOAD =====================
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(DATA_DIR, 'uploads'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || '') ||
        (file.mimetype.startsWith('video/') ? '.mp4' : '.jpg');
      cb(null, newId('m') + ext);
    }
  }),
  limits: { fileSize: 90 * 1024 * 1024 }
});

// ===================== APP =====================
const app = express();
const server = http.createServer(app);
app.use(express.json({ limit: '5mb' }));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads'), {
  maxAge: '7d', immutable: true
}));
app.use(express.static(__dirname));

// --- WS ---
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const user = authFromToken(url.searchParams.get('token'));
  if (!user) { ws.close(4001, 'unauthorized'); return; }
  ws.user = user;
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
  ws.on('error', () => clients.delete(ws));
  ws.send(JSON.stringify({ type: 'hello', userId: user.id, nick: user.nick }));
});

function broadcast(payload, exclude = null) {
  const data = JSON.stringify(payload);
  for (const c of clients) {
    if (c === exclude) continue;
    if (c.readyState === 1) {
      try { c.send(data); } catch (e) {}
    }
  }
}

// ===================== HELPERS =====================
function serializePost(row, myUserId) {
  const likeCount = db.prepare('SELECT COUNT(*) c FROM likes WHERE post_id = ?').get(row.id).c;
  const isLiked = myUserId
    ? !!db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?').get(row.id, myUserId)
    : false;
  const commentCount = db.prepare('SELECT COUNT(*) c FROM comments WHERE post_id = ?').get(row.id).c;
  return {
    id: row.id,
    author: row.author,
    authorId: row.author_id,
    text: row.text,
    type: row.type,
    media: !!row.media_url,
    mediaUrl: row.media_url,
    mimeType: row.mime_type,
    time: row.created_at,
    likeCount,
    commentCount,
    isLiked
  };
}

function getComments(postId) {
  return db.prepare('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC').all(postId)
    .map(c => ({ id: c.id, author: c.author, authorId: c.author_id, text: c.text, time: c.created_at }));
}

// ===================== ROUTES =====================

app.post('/api/login', (req, res) => {
  try {
    const { nick, avatar } = req.body || {};
    const { user, token } = createSession(nick, avatar);
    res.json({ userId: user.id, nick: user.nick, avatar: user.avatar, token });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/me', authMiddleware, (req, res) => {
  const { nick, avatar } = req.body || {};
  if (nick) {
    const cleanNick = String(nick).trim().slice(0, 20);
    if (cleanNick.length < 2) return res.status(400).json({ error: 'nick_too_short' });
    const taken = db.prepare('SELECT id FROM users WHERE nick = ? AND id != ?').get(cleanNick, req.user.id);
    if (taken) return res.status(409).json({ error: 'nick_taken' });
    db.prepare('UPDATE users SET nick = ? WHERE id = ?').run(cleanNick, req.user.id);
  }
  if (avatar !== undefined) {
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar || null, req.user.id);
  }
  const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  broadcast({ type: 'profile', userId: fresh.id, nick: fresh.nick, avatar: fresh.avatar });
  res.json({ userId: fresh.id, nick: fresh.nick, avatar: fresh.avatar });
});

app.get('/api/posts', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  let rows;
  if (q) {
    rows = db.prepare(`
      SELECT * FROM posts
      WHERE lower(text) LIKE ? OR lower(author) LIKE ?
      ORDER BY created_at DESC LIMIT 500
    `).all('%' + q + '%', '%' + q + '%');
  } else {
    rows = db.prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT 500').all();
  }
  res.json(rows.map(r => serializePost(r, req.user.id)));
});

app.get('/api/posts/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json(serializePost(row, req.user.id));
});

app.post('/api/posts', authMiddleware, (req, res) => {
  const { text, type } = req.body || {};
  const t = String(text || '').trim();
  if (!t) return res.status(400).json({ error: 'empty' });
  const id = newId('p');
  const now = Date.now();
  const postType = type === 'video' || type === 'image' ? type : 'text';
  db.prepare(`
    INSERT INTO posts (id, author_id, author, text, type, created_at)
    VALUES (?,?,?,?,?,?)
  `).run(id, req.user.id, req.user.nick, t, postType, now);
  const row = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
  const payload = serializePost(row, req.user.id);
  broadcast({ type: 'post', post: payload });
  res.json(payload);
});

app.post('/api/posts/media', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  const text = String(req.body.text || '').trim();
  const mime = req.file.mimetype || '';
  let type = 'image';
  if (mime.startsWith('video/')) type = 'video';
  else if (!mime.startsWith('image/')) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'bad_type' });
  }
  const id = newId('p');
  const now = Date.now();
  const mediaUrl = '/uploads/' + req.file.filename;
  db.prepare(`
    INSERT INTO posts (id, author_id, author, text, type, media_url, mime_type, created_at)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(id, req.user.id, req.user.nick, text || (req.user.nick + ' запостил медиа'), type, mediaUrl, mime, now);
  const row = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
  const payload = serializePost(row, req.user.id);
  broadcast({ type: 'post', post: payload });
  res.json(payload);
});

app.delete('/api/posts/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.author_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  if (row.media_url && row.media_url.startsWith('/uploads/')) {
    const p = path.join(DATA_DIR, row.media_url);
    fs.unlink(p, () => {});
  }
  db.prepare('DELETE FROM likes WHERE post_id = ?').run(row.id);
  db.prepare('DELETE FROM comments WHERE post_id = ?').run(row.id);
  db.prepare('DELETE FROM posts WHERE id = ?').run(row.id);
  broadcast({ type: 'delete', postId: row.id });
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const existing = db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?')
    .get(row.id, req.user.id);
  if (existing) {
    db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').run(row.id, req.user.id);
  } else {
    db.prepare('INSERT INTO likes (post_id, user_id, created_at) VALUES (?,?,?)')
      .run(row.id, req.user.id, Date.now());
  }
  const likeCount = db.prepare('SELECT COUNT(*) c FROM likes WHERE post_id = ?').get(row.id).c;
  const isLiked = !existing;
  broadcast({ type: 'like', postId: row.id, userId: req.user.id, on: isLiked, likeCount });
  res.json({ likeCount, isLiked });
});

app.get('/api/posts/:id/comments', authMiddleware, (req, res) => {
  res.json(getComments(req.params.id));
});

app.post('/api/posts/:id/comments', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const text = String(req.body?.text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  const id = newId('c');
  const now = Date.now();
  db.prepare(`
    INSERT INTO comments (id, post_id, author_id, author, text, created_at)
    VALUES (?,?,?,?,?,?)
  `).run(id, row.id, req.user.id, req.user.nick, text, now);
  const comment = { id, author: req.user.nick, authorId: req.user.id, text, time: now };
  broadcast({ type: 'comment', postId: row.id, comment });
  res.json(comment);
});

app.get('/api/users/:id', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const postsRows = db.prepare('SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC').all(u.id);
  const postsOut = postsRows.map(r => serializePost(r, req.user.id));
  const totalLikes = postsOut.reduce((s, p) => s + p.likeCount, 0);
  res.json({
    userId: u.id,
    nick: u.nick,
    avatar: u.avatar,
    postCount: postsOut.length,
    totalLikes,
    posts: postsOut
  });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

server.listen(PORT, () => {
  console.log('ZaharkaTok server on port ' + PORT + ', data dir: ' + DATA_DIR);
});