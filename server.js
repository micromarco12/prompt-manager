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
app.use(express.static('public')); // Serve static files from 'public' directory

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-should-be-in-env';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user; // Add user payload to request object
    next();
  });
};

// Initialize database tables if they don't exist
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user', -- 'user' or 'admin'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS directories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        parent_id INTEGER REFERENCES directories(id) ON DELETE CASCADE, -- If parent is deleted, delete child
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL, -- If user is deleted, delete their directories
        is_shared BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (name, parent_id, user_id) -- Allow same name in different folders or for different users
      )
    `);
    // Add an index for frequently queried columns
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_directories_user_id ON directories(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_directories_is_shared ON directories(is_shared);`);


    await pool.query(`
      CREATE TABLE IF NOT EXISTS prompts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        directory_id INTEGER REFERENCES directories(id) ON DELETE CASCADE, -- If directory is deleted, delete its prompts
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL, -- If user is deleted, delete their prompts
        tags TEXT[],
        is_restricted BOOLEAN DEFAULT false, -- If true, only owner or admin can see, even in shared folder
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // Add indexes for frequently queried columns
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_prompts_user_id ON prompts(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_prompts_directory_id ON prompts(directory_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_prompts_tags ON prompts USING GIN(tags);`); // GIN index for array search

    console.log('Database initialized successfully (tables checked/created).');
  } catch (error) {
    console.error('Database initialization error:', error);
    // Consider whether to exit the process if DB init fails critically
  }
}

// --- User Routes ---
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, role',
      [email, hashedPassword]
    );
    const user = result.rows[0];

    // Create a default "My Prompts" directory for the new user
    await pool.query(
        'INSERT INTO directories (name, user_id, is_shared) VALUES ($1, $2, $3)',
        ['My Prompts', user.id, false]
    );

    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    if (error.code === '23505') { // Unique violation (email already exists)
      res.status(409).json({ error: 'Email already exists' });
    } else {
      console.error('Register error:', error);
      res.status(500).json({ error: 'Server error during registration' });
    }
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' } // Token expires in 24 hours
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// --- Directory Routes ---
app.post('/api/directories', authenticateToken, async (req, res) => {
  try {
    const { name, parent_id, is_shared } = req.body;
    const user_id = req.user.id;

    if (!name) {
      return res.status(400).json({ error: 'Directory name is required' });
    }

    // Optional: Check if parent_id belongs to the current user if provided
    if (parent_id) {
        const parentDirResult = await pool.query('SELECT user_id FROM directories WHERE id = $1', [parent_id]);
        if (parentDirResult.rows.length === 0 || parentDirResult.rows[0].user_id !== user_id) {
            // If parent_id is for a shared folder not owned by user, disallow creating subfolder
            // This logic might need adjustment based on sharing rules for subfolders
            // For now, only allow subfolders in own directories.
            const parentDir = await pool.query('SELECT user_id, is_shared FROM directories WHERE id = $1', [parent_id]);
            if (parentDir.rows.length === 0 || (parentDir.rows[0].user_id !== user_id && !parentDir.rows[0].is_shared)) {
                 return res.status(403).json({ error: 'Cannot create subdirectory in a directory you do not own or is not shared.' });
            }
        }
    }


    const result = await pool.query(
      `INSERT INTO directories (name, parent_id, user_id, is_shared)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, parent_id || null, user_id, is_shared || false]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
     if (error.code === '23505') { // unique_violation
        res.status(409).json({ error: 'A directory with this name already exists in the selected location for your account.' });
    } else {
        console.error('Create directory error:', error);
        res.status(500).json({ error: 'Server error creating directory' });
    }
  }
});

app.get('/api/directories', authenticateToken, async (req, res) => {
  try {
    const user_id = req.user.id;
    // Fetch user's own directories AND any directories marked as shared by anyone
    const result = await pool.query(
      `SELECT d.*, u.email as owner_email 
       FROM directories d
       JOIN users u ON d.user_id = u.id
       WHERE d.user_id = $1 OR d.is_shared = true
       ORDER BY d.name`, // Consider ordering by parent_id then name for tree structure
      [user_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get directories error:', error);
    res.status(500).json({ error: 'Server error fetching directories' });
  }
});

app.put('/api/directories/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, parent_id, is_shared } = req.body;
    const user_id = req.user.id;

    if (!name) {
        return res.status(400).json({ error: 'Directory name is required' });
    }

    try {
        // Check if the directory exists and belongs to the user
        const dirCheck = await pool.query('SELECT * FROM directories WHERE id = $1 AND user_id = $2', [id, user_id]);
        if (dirCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Directory not found or you do not have permission to edit it.' });
        }

        // Prevent moving a directory into itself or its own descendants (more complex check needed for full protection)
        if (parent_id && parseInt(parent_id) === parseInt(id)) {
            return res.status(400).json({ error: 'Cannot move a directory into itself.' });
        }
        // Add more checks if parent_id is a descendant

        const result = await pool.query(
            `UPDATE directories 
             SET name = $1, parent_id = $2, is_shared = $3, updated_at = CURRENT_TIMESTAMP 
             WHERE id = $4 AND user_id = $5
             RETURNING *`,
            [name, parent_id || null, is_shared || false, id, user_id]
        );

        if (result.rows.length === 0) {
             return res.status(404).json({ error: 'Directory not found or update failed.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        if (error.code === '23505') { // unique_violation
            res.status(409).json({ error: 'A directory with this name already exists in the selected location for your account.' });
        } else {
            console.error('Update directory error:', error);
            res.status(500).json({ error: 'Server error updating directory' });
        }
    }
});


app.delete('/api/directories/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const user_id = req.user.id;
  const client = await pool.connect(); // Use a client for transaction

  try {
    await client.query('BEGIN'); // Start transaction

    // Check if the directory exists and belongs to the user
    const dirResult = await client.query('SELECT * FROM directories WHERE id = $1 AND user_id = $2', [id, user_id]);
    if (dirResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Directory not found or you do not have permission to delete it.' });
    }
    
    // The ON DELETE CASCADE on parent_id in directories table and directory_id in prompts table
    // should handle deleting children and prompts automatically.

    const deleteResult = await client.query('DELETE FROM directories WHERE id = $1 AND user_id = $2', [id, user_id]);

    if (deleteResult.rowCount === 0) {
        await client.query('ROLLBACK');
        // This case should ideally be caught by the check above, but as a safeguard:
        return res.status(404).json({ error: 'Directory not found or deletion failed unexpectedly.'});
    }

    await client.query('COMMIT'); // Commit transaction
    res.json({ message: 'Directory and all its contents deleted successfully' });
  } catch (error) {
    await client.query('ROLLBACK'); // Rollback on error
    console.error('Delete directory error:', error);
    // Check for foreign key violation if not using ON DELETE CASCADE or if it fails
    if (error.code === '23503') { // foreign_key_violation
        return res.status(400).json({ error: 'Cannot delete directory because it is referenced by other items. Ensure ON DELETE CASCADE is working or handle manually.' });
    }
    res.status(500).json({ error: 'Server error deleting directory' });
  } finally {
    client.release(); // Release client back to the pool
  }
});


// --- Prompt Routes ---
app.post('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const { title, content, directory_id, tags, is_restricted } = req.body;
    const user_id = req.user.id;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    if (!directory_id) {
        return res.status(400).json({ error: 'Directory ID is required' });
    }

    // Verify directory_id belongs to user or is a shared directory they can post to
    const dirCheck = await pool.query('SELECT user_id, is_shared FROM directories WHERE id = $1', [directory_id]);
    if (dirCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Directory not found.' });
    }
    // Basic check: user owns the directory or it's a shared one.
    // More granular permissions for shared directories could be added (e.g., write access list)
    if (dirCheck.rows[0].user_id !== user_id && !dirCheck.rows[0].is_shared) {
        return res.status(403).json({ error: 'You do not have permission to save prompts to this directory.' });
    }


    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags, is_restricted, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
       RETURNING *`,
      [title, content, directory_id, user_id, tags || [], is_restricted || false]
    );
    const newPrompt = result.rows[0];
    // Add author email and directory name for immediate use in frontend if needed
    newPrompt.author_email = req.user.email;
    newPrompt.directory_name = dirCheck.rows[0].name; // Assuming dirCheck has the name

    res.status(201).json(newPrompt);
  } catch (error) {
    console.error('Create prompt error:', error);
    res.status(500).json({ error: 'Server error creating prompt' });
  }
});

app.get('/api/prompts', authenticateToken, async (req, res) => {
  try {
    const user_id = req.user.id;
    const user_role = req.user.role;
    const { directory_id, search } = req.query;

    let query = `
      SELECT p.*, u.email as author_email, d.name as directory_name
      FROM prompts p
      JOIN users u ON p.user_id = u.id
      LEFT JOIN directories d ON p.directory_id = d.id
    `;
    const params = [];
    const conditions = [];

    // Base visibility: User sees their own prompts OR prompts in shared directories
    // OR prompts if they are an admin (admin sees all, unless further restricted)
    let visibilityCondition = `(p.user_id = $${params.length + 1}`;
    params.push(user_id);
    visibilityCondition += ` OR d.is_shared = true)`;

    // If user is admin, they can see everything, but respect is_restricted for non-admins
    if (user_role !== 'admin') {
        visibilityCondition += ` AND (d.is_shared = false OR p.is_restricted = false OR p.user_id = $${params.length + 1})`;
        params.push(user_id); // re-push user_id for this part of OR
    }
    conditions.push(`(${visibilityCondition})`);


    if (directory_id) {
      conditions.push(`p.directory_id = $${params.length + 1}`);
      params.push(parseInt(directory_id));
    }

    if (search) {
      conditions.push(`(p.title ILIKE $${params.length + 1} OR p.content ILIKE $${params.length + 1} OR $${params.length + 2} = ANY(p.tags))`);
      params.push(`%${search}%`);
      params.push(search); // For tag search
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY p.updated_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get prompts error:', error);
    res.status(500).json({ error: 'Server error fetching prompts' });
  }
});

app.put('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params; // Prompt ID
    const { title, content, directory_id, tags, is_restricted } = req.body;
    const user_id = req.user.id;
    const user_role = req.user.role;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    if (!directory_id) {
        return res.status(400).json({ error: 'Directory ID is required' });
    }

    // Check ownership or admin role
    const ownershipCheck = await pool.query('SELECT user_id FROM prompts WHERE id = $1', [id]);
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    if (ownershipCheck.rows[0].user_id !== user_id && user_role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to edit this prompt' });
    }
    
    // Verify target directory_id belongs to user or is a shared directory they can post to
    const dirCheck = await pool.query('SELECT user_id, is_shared FROM directories WHERE id = $1', [directory_id]);
    if (dirCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Target directory not found.' });
    }
    if (dirCheck.rows[0].user_id !== user_id && !dirCheck.rows[0].is_shared && user_role !== 'admin') {
        // If moving to a directory not owned and not shared, and user is not admin
        return res.status(403).json({ error: 'You do not have permission to move prompts to this target directory.' });
    }


    const result = await pool.query(
      `UPDATE prompts
       SET title = $1, content = $2, directory_id = $3, tags = $4, is_restricted = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6
       RETURNING *`,
      [title, content, directory_id, tags || [], is_restricted || false, id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Prompt not found or update failed.' });
    }
    const updatedPrompt = result.rows[0];
    // Add author email and directory name for immediate use in frontend
    const authorInfo = await pool.query('SELECT email FROM users WHERE id = $1', [updatedPrompt.user_id]);
    updatedPrompt.author_email = authorInfo.rows[0]?.email;
    const dirInfo = await pool.query('SELECT name FROM directories WHERE id = $1', [updatedPrompt.directory_id]);
    updatedPrompt.directory_name = dirInfo.rows[0]?.name;


    res.json(updatedPrompt);
  } catch (error) {
    console.error('Update prompt error:', error);
    res.status(500).json({ error: 'Server error updating prompt' });
  }
});

app.delete('/api/prompts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params; // Prompt ID
    const user_id = req.user.id;
    const user_role = req.user.role;

    // Check ownership or admin role
    const ownershipCheck = await pool.query('SELECT user_id FROM prompts WHERE id = $1', [id]);
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    if (ownershipCheck.rows[0].user_id !== user_id && user_role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to delete this prompt' });
    }

    await pool.query('DELETE FROM prompts WHERE id = $1', [id]);
    res.json({ message: 'Prompt deleted successfully' });
  } catch (error) {
    console.error('Delete prompt error:', error);
    res.status(500).json({ error: 'Server error deleting prompt' });
  }
});

// --- Chrome Extension Route (Example) ---
app.post('/api/chrome-extension/save', authenticateToken, async (req, res) => {
  try {
    const { text, url, title: providedTitle } = req.body;
    const user_id = req.user.id;

    if (!text) {
      return res.status(400).json({ error: 'Text content is required' });
    }

    const promptTitle = providedTitle || `Saved from ${url ? new URL(url).hostname : 'Chrome'}`;

    // Find or create "Chrome Saves" directory for the user
    let directoryResult = await pool.query(
      'SELECT id FROM directories WHERE name = $1 AND user_id = $2',
      ['Chrome Saves', user_id]
    );
    let directoryId;
    if (directoryResult.rows.length === 0) {
      const newDir = await pool.query(
        'INSERT INTO directories (name, user_id) VALUES ($1, $2) RETURNING id',
        ['Chrome Saves', user_id]
      );
      directoryId = newDir.rows[0].id;
    } else {
      directoryId = directoryResult.rows[0].id;
    }

    const result = await pool.query(
      `INSERT INTO prompts (title, content, directory_id, user_id, tags, updated_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
       RETURNING *`,
      [promptTitle, text, directoryId, user_id, ['chrome-extension', 'saved']]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Chrome extension save error:', error);
    res.status(500).json({ error: 'Server error saving from Chrome extension' });
  }
});


// Serve the frontend (index.html) for the root path
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Global error handler (optional, for unhandled errors)
app.use((err, req, res, next) => {
    console.error("Unhandled application error:", err.stack);
    res.status(500).send('Something broke!');
});


// Start server and initialize database
app.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend available at http://localhost:${PORT}`);
});
