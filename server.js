// server.js
// Backend server for shift management application using Node.js, Express.js, PostgreSQL
// Technologies: Express, pg, bcryptjs, jsonwebtoken, cors, dotenv
// Author: Backend Expert

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// Helper: JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Helper: Admin Middleware
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

// --- AUTH ROUTES ---
// Đăng nhập cho admin
app.post('/api/v1/auth/admin/login', async (req, res) => {
  const { employee_id, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT employee_id, password_hash, is_admin, is_password_default FROM data_nhanvien WHERE employee_id = $1',
      [employee_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = result.rows[0];
    if (!user.is_admin) {
      return res.status(403).json({ message: 'Not an admin account' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Incorrect password' });
    }
    const token = jwt.sign(
      { employee_id: user.employee_id, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, is_password_default: user.is_password_default });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Đăng nhập cho nhân viên thường
app.post('/api/v1/auth/staff/login', async (req, res) => {
  const { employee_id, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT employee_id, password_hash, is_admin, is_password_default FROM data_nhanvien WHERE employee_id = $1',
      [employee_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = result.rows[0];
    if (user.is_admin) {
      return res.status(403).json({ message: 'Not a staff account' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Incorrect password' });
    }
    const token = jwt.sign(
      { employee_id: user.employee_id, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, is_password_default: user.is_password_default });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { new_password } = req.body;
  const { employee_id } = req.user;
  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query(
      'UPDATE data_nhanvien SET password_hash = $1, is_password_default = false WHERE employee_id = $2',
      [hash, employee_id]
    );
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --- SCHEDULE ROUTES (Employee) ---
app.get('/api/schedules', authenticateToken, async (req, res) => {
  const { employee_id } = req.user;
  const { month, year } = req.query;
  try {
    const result = await pool.query(
      `SELECT es.id, es.schedule_date, s.shift_name, es.shift_part, es.status
       FROM employee_schedules es
       JOIN shifts s ON es.shift_id = s.id
       WHERE es.employee_id = $1 AND EXTRACT(MONTH FROM es.schedule_date) = $2 AND EXTRACT(YEAR FROM es.schedule_date) = $3
       ORDER BY es.schedule_date ASC`,
      [employee_id, month, year]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/schedules', authenticateToken, async (req, res) => {
  const { employee_id } = req.user;
  const schedules = req.body;
  if (!Array.isArray(schedules)) {
    return res.status(400).json({ message: 'Invalid request body' });
  }
  try {
    // Check for conflicts
    for (const sch of schedules) {
      const conflict = await pool.query(
        'SELECT 1 FROM employee_schedules WHERE employee_id = $1 AND shift_id = $2 AND schedule_date = $3',
        [employee_id, sch.shift_id, sch.schedule_date]
      );
      if (conflict.rows.length > 0) {
        return res.status(409).json({ message: `Conflict: Already registered for shift_id ${sch.shift_id} on ${sch.schedule_date}` });
      }
    }
    // Insert schedules
    for (const sch of schedules) {
      await pool.query(
        'INSERT INTO employee_schedules (employee_id, shift_id, schedule_date, shift_part, status) VALUES ($1, $2, $3, $4, $5)',
        [employee_id, sch.shift_id, sch.schedule_date, sch.shift_part, 'pending']
      );
    }
    res.status(201).json({ message: 'Schedules created successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --- ADMIN ROUTES ---
app.get('/api/admin/schedules', authenticateToken, requireAdmin, async (req, res) => {
  const { month, year, phong_ban } = req.query;
  let query = `SELECT es.id, dn.ho_va_ten, dn.phong_ban, es.schedule_date, s.shift_name, es.shift_part, es.status
               FROM employee_schedules es
               JOIN shifts s ON es.shift_id = s.id
               JOIN data_nhanvien dn ON es.employee_id = dn.employee_id
               WHERE EXTRACT(MONTH FROM es.schedule_date) = $1 AND EXTRACT(YEAR FROM es.schedule_date) = $2`;
  const params = [month, year];
  if (phong_ban) {
    query += ' AND dn.phong_ban = $3';
    params.push(phong_ban);
  }
  query += ' ORDER BY es.schedule_date ASC';
  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/schedules/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status' });
  }
  try {
    const update = await pool.query(
      'UPDATE employee_schedules SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    if (update.rows.length === 0) {
      return res.status(404).json({ message: 'Schedule not found' });
    }
    res.json(update.rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --- UTILITY ROUTES ---
app.get('/api/shifts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, shift_name FROM shifts ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
  const { employee_id } = req.user;
  try {
    const result = await pool.query(
      'SELECT employee_id, ho_va_ten, email, phong_ban FROM data_nhanvien WHERE employee_id = $1',
      [employee_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --- SERVER START ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// --- END OF FILE ---
