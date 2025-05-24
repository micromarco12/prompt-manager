const express = require('express');
const cors = require('cors');
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

// 🔓 BYPASS LOGIN
function auth(req, res, next) {
  req.user = { id: 1, email: 'demo@example.com', role: 'admin' };
  next();
}

app.get('/api/directories', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM directories WHERE user_id = $1 OR is_shared = TRUE ORDER BY id',
      [1]
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/directories', auth, async (req, res) => {
  const { name, parent_id = null, is_shared = false } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO directories(name, parent_id, user_id, is_shared) VALUES($1,$2,$3,$4) RETURNING *',
      [name, parent_id, 1, is_shared]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/directories/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM directories WHERE id=$1', [id]);
    res.json({ message: 'Directory deleted' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/prompts', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.*, u.email AS author_email FROM prompts p
       JOIN directories d ON d.id = p.directory_id
       JOIN users u ON u.id = p.user_id
       WHERE p.user_id = $1 OR d.is_shared = TRUE
       ORDER BY p.updated_at DESC`,
      [1]
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/prompts', auth, async (req, res) => {
  const { title, content, tags = [], directory_id } = req.body;
  if (!title || !content || !directory_id) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO prompts(title, content, tags, directory_id, user_id) VALUES($1, $2, $3, $4, $5) RETURNING *',
      [title, content, tags, directory_id, 1]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/prompts/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { title, content, tags } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE prompts SET title = $1, content = $2, tags = $3, updated_at = NOW() WHERE id = $4 RETURNING *',
      [title, content, tags, id]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/prompts/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM prompts WHERE id=$1', [id]);
    res.json({ message: 'Prompt deleted' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (_, res) => res.sendFile(__dirname + '/public/index.html'));

app.listen(PORT, async () => {
  await initialiseDb();
  console.log(`🚀 Prompt-Manager running on ${PORT}`);
});
