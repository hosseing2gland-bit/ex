const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = 'your_super_secret_key_change_this'; // Important: Change this!
const SALT_ROUNDS = 10;

// Middleware
const corsOptions = {
  origin: '*', // Allow all origins
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  allowedHeaders: 'Content-Type, Authorization', // Explicitly allow Authorization header
};
app.use(cors(corsOptions));
app.use(express.json());

// Database Setup
const dbPath = path.join(process.env.RENDER_DISK_MOUNT_PATH || __dirname, 'orders.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // Users Table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Orders Table
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id TEXT NOT NULL,
      order_link TEXT NOT NULL,
      title TEXT,
      description TEXT,
      priority TEXT NOT NULL,
      sender TEXT NOT NULL,
      assigned_to TEXT NOT NULL,
      status TEXT DEFAULT 'ارسال شده',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// WebSocket connections (unchanged)
const connections = new Map();
wss.on('connection', (ws) => {
    ws.on('message', (data) => {
        const msg = JSON.parse(data);
        if (msg.type === 'register') {
            connections.set(msg.specialist, ws);
            console.log(`✅ ${msg.specialist} متصل شد`);
        }
    });
    ws.on('close', () => {
        connections.forEach((value, key) => {
            if (value === ws) connections.delete(key);
        });
    });
});


// ===== AUTH API =====

// Register User
app.post('/api/users/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'نام کاربری و رمز عبور الزامی است.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(409).json({ success: false, message: 'این نام کاربری قبلا ثبت شده است.' });
                }
                return res.status(500).json({ success: false, message: 'خطا در ثبت کاربر.' });
            }
            res.status(201).json({ success: true, message: 'کاربر با موفقیت ثبت شد.' });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'خطای داخلی سرور.' });
    }
});

// Login User
app.post('/api/users/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'نام کاربری و رمز عبور الزامی است.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'خطای داخلی سرور.' });
        }
        if (!user) {
            return res.status(401).json({ success: false, message: 'نام کاربری یا رمز عبور اشتباه است.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
            res.json({ success: true, token });
        } else {
            res.status(401).json({ success: false, message: 'نام کاربری یا رمز عبور اشتباه است.' });
        }
    });
});

// ===== Middleware to verify JWT =====
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Get all users (for specialist dropdown)
app.get('/api/users', authenticateToken, (req, res) => {
    db.all('SELECT username FROM users ORDER BY username', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'خطا در دریافت لیست کاربران.' });
        }
        res.json({ success: true, users: rows });
    });
});

// ===== ORDERS API (Now Protected) =====

// Send Order
app.post('/api/orders/send', authenticateToken, (req, res) => {
    const { ticket_id, order_link, title, description, priority, assigned_to } = req.body;
    const sender = req.user.username; // Get sender from authenticated user

    db.run(
        `INSERT INTO orders (ticket_id, order_link, title, description, priority, sender, assigned_to, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'ارسال شده')`,
        [ticket_id, order_link, title || 'بدون عنوان', description || '', priority, sender, assigned_to],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            const order_id = this.lastID;
            const notificationMessage = `سفارش جدید از ${sender}`;

            // Notify via WebSocket
            const specialistWs = connections.get(assigned_to);
            if (specialistWs && specialistWs.readyState === WebSocket.OPEN) {
                specialistWs.send(JSON.stringify({ type: 'new_order', order_id, sender, title }));
            }
            
            res.json({ success: true, order_id });
        }
    );
});

// Get Orders for Specialist
app.get('/api/orders/specialist/:name', authenticateToken, (req, res) => {
    // Ensure user can only fetch their own orders
    if (req.user.username !== req.params.name) {
        return res.status(403).json({ error: 'Forbidden' });
    }
  
    db.all(
        `SELECT * FROM orders WHERE assigned_to = ? ORDER BY created_at DESC`,
        [req.params.name],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

// Update Order Status
app.put('/api/orders/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    const order_id = req.params.id;
  
    db.run(
        `UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [status, order_id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'Order not found' });

            res.json({ success: true });
        }
    );
});


const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 سرور در پورت ${PORT} و روی تمام آدرس‌های شبکه اجرا می‌شود`);
});
