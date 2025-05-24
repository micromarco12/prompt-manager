const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

/* ─────────────────────  MIDDLEWARE  ───────────────────── */
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

/* ─────────────────────  DATABASE  ───────────────────── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

/* ─ Init tables if they don’t exist yet ─ */
async function initialiseDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS directories (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      parent_id INTEGER REFERENCES directories(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      is_shared BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS prompts (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      tags TEXT[] DEFAULT '{}',
      is_restricted BOOLEAN DEFAULT FALSE,
      directory_id INTEGER REFERENCES directories(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Database ready');
}

/* ─────────────────────  HELPERS  ───────────────────── */
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const makeToken = user =>
  jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const tok = hdr.split(' ')[1];
  if (!tok) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(tok, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

/* ─────────────────────  AUTH ROUTES  ───────────────────── */
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING *',
      [email.toLowerCase(), hash]
    );
    res.status(201).json({ token: makeToken(rows[0]), user: { id: rows[0].id, email: rows[0].email, role: rows[0].role } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: makeToken(rows[0]), user: { id: rows[0].id, email: rows[0].email, role: rows[0].role } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ──────────────────  DIRECTORY ROUTES  ────────────────── */
app.get('/api/directories', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM directories WHERE user_id=$1 OR is_shared=TRUE ORDER BY id`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/directories', auth, async (req, res) => {
  const { name, parent_id = null, is_shared = false } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO directories(name, parent_id, user_id, is_shared) VALUES($1,$2,$3,$4) RETURNING *`,
      [name, parent_id, req.user.id, is_shared]
    );
    res.status(201).json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/directories/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('SELECT user_id FROM directories WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Unauthorised' });
    await pool.query('DELETE FROM directories WHERE id=$1', [id]);
    res.json({ message: 'Directory deleted' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});
