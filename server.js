const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

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
  console.log('✅ Database initialized');
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING *',
      [email.toLowerCase(), hash]
    );
    res.status(201).json({ token: makeToken(rows[0]), user: { id: rows[0].id, email: rows[0].email, role: rows[0].role } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: makeToken(rows[0]), user: { id: rows[0].id, email: rows[0].email, role: rows[0].role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/directories', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM directories WHERE user_id = $1 OR is_shared = TRUE ORDER BY id', [1]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/directories', async (req, res) => {
  const { name, parent_id = null, is_shared = false } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO directories(name, parent_id, user_id, is_shared) VALUES($1, $2, $3, $4) RETURNING *',
      [name, parent_id, req.user.id, is_shared]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/directories', async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('SELECT user_id FROM directories WHERE id = $1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Directory not found' });
    if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Unauthorized' });
    await pool.query('DELETE FROM directories WHERE id = $1', [id]);
    res.json({ message: 'Directory deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/prompts', auth, async (req, res) => {
  const { user_only, directory } = req.query;
  try {
    let query = `
      SELECT p.*, u.email AS author_email FROM prompts p
      JOIN directories d ON d.id = p.directory_id
      JOIN users u ON u.id = p.user_id WHERE 1=1`;
    const params = [];

    if (user_only === 'true') {
      params.push(req.user.id);
      query += ` AND p.user_id = $${params.length}`;
    }

    if (directory) {
      params.push(directory);
      query += ` AND d.name = $${params.length}`;
    }

    query += ' ORDER BY p.updated_at DESC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/prompts', auth, async (req, res) => {
  const { title, content, tags = [], directory_id } = req.body;
  if (!title || !content || !directory_id) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO prompts(title, content, tags, directory_id, user_id) VALUES($1, $2, $3, $4, $5) RETURNING *',
      [title, content, tags, directory_id, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/prompts/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { title, content, tags } = req.body;
  try {
    const { rows: own } = await pool.query('SELECT * FROM prompts WHERE id = $1', [id]);
    if (!own.length) return res.status(404).json({ error: 'Not found' });
    if (own[0].user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Unauthorized' });
    const { rows } = await pool.query(
      'UPDATE prompts SET title = $1, content = $2, tags = $3, updated_at = NOW() WHERE id = $4 RETURNING *',
      [title, content, tags, id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/prompts/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: own } = await pool.query('SELECT user_id FROM prompts WHERE id = $1', [id]);
    if (!own.length) return res.status(404).json({ error: 'Not found' });
    if (own[0].user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Unauthorized' });
    await pool.query('DELETE FROM prompts WHERE id = $1', [id]);
    res.json({ message: 'Prompt deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (_, res) => res.sendFile(__dirname + '/public/index.html'));

app.listen(PORT, async () => {
  await initialiseDb();
  console.log(`🚀 Prompt-Manager running on ${PORT}`);
});
