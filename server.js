const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

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
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Initialize database
async function initializeDatabase() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create directories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS directories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        parent_id INTEGER REFERENCES directories(id) ON DELETE CASCADE,
        is_shared BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(name, user_id, parent_id)
      )
    `);

    // Create prompts table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS prompts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        directory_id INTEGER REFERENCES directories(id) ON DELETE SET NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        tags TEXT[],
        restricted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Cleanup duplicate directories
async function cleanupDuplicateDirectories() {
  try {
    // Remove duplicate directories, keeping only the first one
    await pool.query(`
      DELETE FROM directories a
      USING directories b
      WHERE a.id > b.id
      AND a.name = b.name
      AND a.user_id = b.user_id
    `);
    console.log('Cleaned up duplicate directories');
  } catch (error) {
    console.error('Error cleaning up directories:', error);
  }
}

// API Routes

// Register new user
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, role',
      [email, passwordHash]
    );

    const user = result.rows[0];

    // Create default directories for the user
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
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
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
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Get directories
app.get('/api/directories', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      'SELECT * FROM directories WHERE user_id = $1 OR is_shared = true ORDER BY name',
      [userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching directories:', error);
    res.status(500).json({ error: 'Failed to fetch directories' });
  }
});

// Create directory
app.post('/api/directories', authenticateToken, async (req, res) => {
  try {
    const { name, parent_id, is_shared } = req.body;
    const userId = req.user.id;

    const result = await pool.query(
      'INSERT INTO directories (name, user_id, parent_id, is_shared) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, userId, parent_id || null, is_shared || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating directory:', error);
    if (error.code === '23505') { // Unique violation
      res.status(400).json({ error: 'Directory with this name already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create directory' });
    }
  }
});

// Update directory (rename)
app.put('/api/directories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    const userId = req.user.id;

    const result = await pool.query(
      'UPDATE directories SET name = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
      [name, id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Directory not found or unauthorized' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating directory:', error);
    res.status(500).json({ error: 'Failed to update directory' });
  }
});

// Delete directory
app.delete('/api/directories/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // First, move all prompts in this directory to the user's default directory
    const defaultDir = await pool.query(
      'SELECT id FROM directories WHERE user_id = $1 AND name = $2',
      [userId, 'My Prompts']
    );

    if (defaultDir.rows.length > 0) {
      await pool.query(
        'UPDATE prompts SET directory_id = $1 WHERE directory_id = $2 AND user_id = $3',
        [defaultDir.rows[0].id, id, userId]
      );
    }

    // Then delete the directory
    const result = await pool.query(
      'DELETE FROM directories WHERE id = $1 AND user_id = $2 AND name NOT IN ($3, $4) RETURNING *',
      [id, userId, 'My Prompts', 'Shared Prompts']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Directory not found or cannot be deleted' });
    }

    res.json({ message: 'Directory deleted successfully' });
  } catch (error) {
    console.error('Error deleting directory:', error);
    res.status(500).json({ error: 'Failed to delete directory' });
  }
});

// Get prompts with proper filtering
app.get('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { user_only, directory } = req.query;
    
    let query;
    let params;
    
    if (user_only === 'true') {
      query = `
        SELECT p.*, u.email as author_email, d.name as directory_name 
        FROM prompts p
        JOIN users u ON p.user_id = u.id
        JOIN directories d ON p.directory_id = d.id
        WHERE p.user_id = $1
        ORDER BY p.created_at DESC
      `;
      params = [userId];
    } else if (directory) {
      // Directory parameter is the directory ID
      query = `
        SELECT p.*, u.email as author_email, d.name as directory_name 
        FROM prompts p
        JOIN users u ON p.user_id = u.id
        JOIN directories d ON p.directory_id = d.id
        WHERE p.directory_id = $1 AND (p.user_id = $2 OR d.is_shared = true)
        ORDER BY p.created_at DESC
      `;
      params = [parseInt(directory), userId];
    } else {
      // All prompts user has access to
      query = `
        SELECT p.*, u.email as author_email, d.name as directory_name 
        FROM prompts p
        JOIN users u ON p.user_id = u.id
        JOIN directories d ON p.directory_id = d.id
        WHERE p.user_id = $1 OR d.is_shared = true
        ORDER BY p.created_at DESC
      `;
      params = [userId];
    }
    
    const result = await pool.query(query, params);
    
    // Add cache prevention headers
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching prompts:', error);
    res.status(500).json({ error: 'Failed to fetch prompts' });
  }
});

// Create prompt
app.post('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const { title, content, directory_id, tags, restricted } = req.body;
    const userId = req.user.id;

    // Verify directory exists and user has access
    const dirCheck = await pool.query(
      'SELECT id FROM directories WHERE id = $1 AND (user_id = $2 OR is_shared = true)',
      [directory_id, userId]
    );

    if (dirCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid directory' });
    }

    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags, restricted) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, content, directory_id, userId, tags || [], restricted || false]
    );

    // Get the prompt with user info
    const promptWithUser = await pool.query(
      `SELECT p.*, u.email as author_email, d.name as directory_name 
       FROM prompts p
       JOIN users u ON p.user_id = u.id
       JOIN directories d ON p.directory_id = d.id
       WHERE p.id = $1`,
      [result.rows[0].id]
    );

    res.status(201).json(promptWithUser.rows[0]);
  } catch (error) {
    console.error('Error creating prompt:', error);
    res.status(500).json({ error: 'Failed to create prompt' });
  }
});

// Update prompt
app.put('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, tags } = req.body;
    const userId = req.user.id;

    const result = await pool.query(
      `UPDATE prompts 
       SET title = $1, content = $2, tags = $3, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $4 AND (user_id = $5 OR user_id IN (
         SELECT user_id FROM directories WHERE id = prompts.directory_id AND is_shared = true
       ))
       RETURNING *`,
      [title, content, tags || [], id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found or unauthorized' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating prompt:', error);
    res.status(500).json({ error: 'Failed to update prompt' });
  }
});

// Delete prompt
app.delete('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const result = await pool.query(
      'DELETE FROM prompts WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found or unauthorized' });
    }

    res.json({ message: 'Prompt deleted successfully' });
  } catch (error) {
    console.error('Error deleting prompt:', error);
    res.status(500).json({ error: 'Failed to delete prompt' });
  }
});

// Serve the frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize database and start server
initializeDatabase().then(() => {
  cleanupDuplicateDirectories();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
