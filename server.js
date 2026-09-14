import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET;

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      phone: user.phone,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Não autenticado' });
    }

    const token = header.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({ error: 'Sessão inválida' });
  }
}

function admin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  next();
}

async function ensureAdmin() {
  const phone = normalizePhone(process.env.ADMIN_PHONE);
  const password = String(process.env.ADMIN_PASSWORD || '');

  if (!phone || !password) {
    console.log('ADMIN_PHONE ou ADMIN_PASSWORD não configurado.');
    return;
  }

  const result = await pool.query(
    'SELECT * FROM users WHERE phone = $1',
    [phone]
  );

  const hash = await bcrypt.hash(password, 12);

  if (result.rows.length === 0) {
    await pool.query(
      `INSERT INTO users
       (phone, password_hash, role, active)
       VALUES ($1, $2, 'admin', true)`,
      [phone, hash]
    );

    console.log('Administrador criado.');
  } else {
    await pool.query(
      `UPDATE users
       SET password_hash = $1,
           role = 'admin',
           active = true
       WHERE phone = $2`,
      [hash, phone]
    );

    console.log('Administrador atualizado.');
  }
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false });
  }
});

/*
  LOGIN / CADASTRO AUTOMÁTICO

  Telefone novo:
  → cria a conta
  → entra automaticamente

  Telefone existente:
  → confere a senha
  → entra
*/
app.post('/api/auth/login', async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || '');

    if (!phone || password.length < 6) {
      return res.status(400).json({
        error: 'Informe telefone e senha com pelo menos 6 caracteres.'
      });
    }

    let result = await pool.query(
      'SELECT * FROM users WHERE phone = $1',
      [phone]
    );

    let user = result.rows[0];

    if (!user) {
      const hash = await bcrypt.hash(password, 12);

      result = await pool.query(
        `INSERT INTO users
         (phone, password_hash, role, active)
         VALUES ($1, $2, 'user', true)
         RETURNING *`,
        [phone, hash]
      );

      user = result.rows[0];

      console.log('Novo usuário criado:', phone);
    } else {
      if (!user.active) {
        return res.status(403).json({
          error: 'Sua conta está desativada.'
        });
      }

      const validPassword = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!validPassword) {
        return res.status(401).json({
          error: 'Telefone ou senha inválidos.'
        });
      }
    }

    const token = createToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        phone: user.phone,
        role: user.role,
        balance_cents: user.balance_cents
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);

    res.status(500).json({
      error: 'Erro interno do servidor.'
    });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, phone, role, balance_cents, active
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Usuário não encontrado.'
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'Erro interno do servidor.'
    });
  }
});

app.get('/api/packages', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, price_cents, credits
       FROM packages
       WHERE active = true
       ORDER BY price_cents`
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'Erro ao carregar pacotes.'
    });
  }
});

app.get('/api/orders', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, p.name AS package_name
       FROM orders o
       JOIN packages p ON p.id = o.package_id
       WHERE o.user_id = $1
       ORDER BY o.id DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'Erro ao carregar pedidos.'
    });
  }
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, phone, role, balance_cents, active, created_at
       FROM users
       ORDER BY id DESC
       LIMIT 500`
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'Erro ao carregar usuários.'
    });
  }
});

app.patch('/api/orders/:id/status', auth, admin, async (req, res) => {
  try {
    const allowed = [
      'queued',
      'processing',
      'completed',
      'cancelled'
    ];

    if (!allowed.includes(req.body.status)) {
      return res.status(400).json({
        error: 'Status inválido.'
      });
    }

    const result = await pool.query(
      `UPDATE orders
       SET status = $1
       WHERE id = $2
       RETURNING *`,
      [req.body.status, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Pedido não encontrado.'
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'Erro ao atualizar pedido.'
    });
  }
});

app.get('*', (req, res) => {
  res.sendFile(process.cwd() + '/public/app.html');
});

const PORT = Number(process.env.PORT || 3000);

async function start() {
  try {
    await pool.query('SELECT 1');
    await ensureAdmin();

    app.listen(PORT, () => {
      console.log(`MK Painel rodando na porta ${PORT}`);
    });
  } catch (error) {
    console.error('Erro ao iniciar:', error);
    process.exit(1);
  }
}

start();
