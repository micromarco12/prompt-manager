const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Initialize database tables
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS directories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        parent_id INTEGER REFERENCES directories(id),
        user_id INTEGER REFERENCES users(id),
        is_shared BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS prompts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        directory_id INTEGER REFERENCES directories(id),
        user_id INTEGER REFERENCES users(id),
        tags TEXT[],
        is_restricted BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Routes

// Register new user
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, role',
      [email, hashedPassword]
    );
    
    const user = result.rows[0];
    
    // Create default directories for user
    await pool.query(
      'INSERT INTO directories (name, user_id, is_shared) VALUES ($1, $2, $3)',
      ['My Prompts', user.id, false]
    );
    
    await pool.query(
      'INSERT INTO directories (name, user_id, is_shared) VALUES ($1, $2, $3)',
      ['Shared Prompts', user.id, true]
    );
    
    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all prompts (with filtering)
app.get('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const { directory, search, user_only, directory_id } = req.query;
    let query = `
      SELECT p.*, u.email as author_email, d.name as directory_name
      FROM prompts p
      JOIN users u ON p.user_id = u.id
      LEFT JOIN directories d ON p.directory_id = d.id
      WHERE 1=1
    `;
    const params = [];
    let paramCount = 0;

    if (user_only === 'true') {
      paramCount++;
      query += ` AND p.user_id = $${paramCount}`;
      params.push(req.user.id);
    }

    if (directory) {
      paramCount++;
      query += ` AND d.name = $${paramCount}`;
      params.push(directory);
    }
    
    if (directory_id) {
      paramCount++;
      query += ` AND p.directory_id = $${paramCount}`;
      params.push(directory_id);
    }

    if (search) {
      paramCount++;
      query += ` AND (p.title ILIKE $${paramCount} OR p.content ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ' ORDER BY p.created_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create new prompt
app.post('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const { title, content, directory_id, tags, is_restricted } = req.body;
    
    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags, is_restricted)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, content, directory_id, req.user.id, tags || [], is_restricted || false]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update prompt
app.put('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, tags, directory_id } = req.body;
    
    // Check ownership or admin
    const ownership = await pool.query(
      'SELECT user_id FROM prompts WHERE id = $1',
      [id]
    );
    
    if (ownership.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    if (ownership.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Building the query dynamically based on what's provided
    let updateQuery = 'UPDATE prompts SET updated_at = CURRENT_TIMESTAMP';
    const params = [];
    let paramCount = 0;
    
    if (title) {
      paramCount++;
      updateQuery += `, title = $${paramCount}`;
      params.push(title);
    }
    
    if (content) {
      paramCount++;
      updateQuery += `, content = $${paramCount}`;
      params.push(content);
    }
    
    if (tags) {
      paramCount++;
      updateQuery += `, tags = $${paramCount}`;
      params.push(tags);
    }
    
    if (directory_id) {
      paramCount++;
      updateQuery += `, directory_id = $${paramCount}`;
      params.push(directory_id);
    }
    
    paramCount++;
    updateQuery += ` WHERE id = $${paramCount} RETURNING *`;
    params.push(id);
    
    const result = await pool.query(updateQuery, params);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Copy prompt to different directory
app.post('/api/prompts/:id/copy', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { directory_id } = req.body;
    
    // Get the original prompt
    const promptResult = await pool.query(
      'SELECT * FROM prompts WHERE id = $1',
      [id]
    );
    
    if (promptResult.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    const originalPrompt = promptResult.rows[0];
    
    // Check permissions - either the user owns the prompt or is an admin
    if (originalPrompt.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Create a copy of the prompt in the new directory
    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags, is_restricted)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        originalPrompt.title + ' (Copy)',
        originalPrompt.content,
        directory_id,
        req.user.id,
        originalPrompt.tags,
        originalPrompt.is_restricted
      ]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete prompt
app.delete('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check ownership or admin
    const ownership = await pool.query(
      'SELECT user_id FROM prompts WHERE id = $1',
      [id]
    );
    
    if (ownership.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    if (ownership.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    await pool.query('DELETE FROM prompts WHERE id = $1', [id]);
    res.json({ message: 'Prompt deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get directories
app.get('/api/directories', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM directories 
       WHERE user_id = $1 OR is_shared = true
       ORDER BY name`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create directory
app.post('/api/directories', authenticateToken, async (req, res) => {
  try {
    const { name, parent_id, is_shared } = req.body;
    
    const result = await pool.query(
      `INSERT INTO directories (name, parent_id, user_id, is_shared)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, parent_id, req.user.id, is_shared || false]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update directory
app.put('/api/directories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, parent_id, is_shared } = req.body;
    
    // Check ownership or admin
    const ownership = await pool.query(
      'SELECT user_id FROM directories WHERE id = $1',
      [id]
    );
    
    if (ownership.rows.length === 0) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    if (ownership.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Building the query dynamically based on what's provided
    let updateQuery = 'UPDATE directories SET';
    const params = [];
    let paramCount = 0;
    let isFirstParam = true;
    
    if (name) {
      paramCount++;
      updateQuery += ` name = $${paramCount}`;
      params.push(name);
      isFirstParam = false;
    }
    
    if (parent_id !== undefined) {
      paramCount++;
      updateQuery += isFirstParam ? ` parent_id = $${paramCount}` : `, parent_id = $${paramCount}`;
      params.push(parent_id);
      isFirstParam = false;
    }
    
    if (is_shared !== undefined) {
      paramCount++;
      updateQuery += isFirstParam ? ` is_shared = $${paramCount}` : `, is_shared = $${paramCount}`;
      params.push(is_shared);
    }
    
    paramCount++;
    updateQuery += ` WHERE id = $${paramCount} RETURNING *`;
    params.push(id);
    
    const result = await pool.query(updateQuery, params);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete directory
app.delete('/api/directories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { move_prompts_to } = req.query;
    
    // Check ownership or admin
    const ownership = await pool.query(
      'SELECT user_id FROM directories WHERE id = $1',
      [id]
    );
    
    if (ownership.rows.length === 0) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    if (ownership.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // If move_prompts_to is provided, move prompts to that directory
    if (move_prompts_to) {
      await pool.query(
        'UPDATE prompts SET directory_id = $1 WHERE directory_id = $2',
        [move_prompts_to, id]
      );
    }
    
    // Now delete the directory
    await pool.query('DELETE FROM directories WHERE id = $1', [id]);
    
    res.json({ message: 'Directory deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Chrome extension endpoint - Save highlighted text
app.post('/api/chrome-extension/save', authenticateToken, async (req, res) => {
  try {
    const { text, url, title } = req.body;
    
    // Auto-generate title if not provided
    const promptTitle = title || `Saved from ${new URL(url).hostname}`;
    
    // Find or create "Chrome Saves" directory
    let directoryResult = await pool.query(
      'SELECT id FROM directories WHERE name = $1 AND user_id = $2',
      ['Chrome Saves', req.user.id]
    );
    
    let directoryId;
    if (directoryResult.rows.length === 0) {
      const newDir = await pool.query(
        'INSERT INTO directories (name, user_id) VALUES ($1, $2) RETURNING id',
        ['Chrome Saves', req.user.id]
      );
      directoryId = newDir.rows[0].id;
    } else {
      directoryId = directoryResult.rows[0].id;
    }
    
    // Save prompt
    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [promptTitle, text, directoryId, req.user.id, ['chrome-extension', 'saved']]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`Server running on port ${PORT}`);
});
