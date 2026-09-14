import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import crypto from 'node:crypto';

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
      return res.status(401).json({
        error: 'Não autenticado'
      });
    }

    const token = header.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: 'Sessão inválida'
    });
  }
}

function admin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: 'Acesso negado'
    });
  }

  next();
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      phone VARCHAR(30) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK(role IN ('user','admin')),
      balance_cents BIGINT NOT NULL DEFAULT 0
        CHECK(balance_cents >= 0),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS packages (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      price_cents BIGINT NOT NULL
        CHECK(price_cents > 0),
      credits INTEGER NOT NULL
        CHECK(credits > 0),
      active BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount_cents BIGINT NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      provider VARCHAR(30) NOT NULL DEFAULT 'mercadopago',
      provider_payment_id VARCHAR(100) UNIQUE,
      external_reference VARCHAR(100) UNIQUE NOT NULL,
      qr_code TEXT,
      qr_code_base64 TEXT,
      approved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      package_id BIGINT NOT NULL REFERENCES packages(id),
      group_link TEXT NOT NULL,
      credits INTEGER NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'queued',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      CHECK (group_link LIKE 'https://chat.whatsapp.com/%')
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      action VARCHAR(100) NOT NULL,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    INSERT INTO packages(name, price_cents, credits)
    VALUES
      ('30 saldo - R$ 30', 3000, 1),
      ('60 saldo - R$ 60', 6000, 2),
      ('100 saldo - R$ 100', 10000, 4)
    ON CONFLICT DO NOTHING;
  `);

  console.log('Banco inicializado com sucesso.');
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

app.post('/api/payments/pix', auth, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || Number(amount) < 30) {
      return res.status(400).json({
        error: 'O valor mínimo é R$ 30,00'
      });
    }

    const response = await fetch(
      'https://api.mercadopago.com/v1/payments',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
          'X-Idempotency-Key': crypto.randomUUID()
        },
        body: JSON.stringify({
  transaction_amount: Number(amount),
  description: 'Crédito MK Painel Divulgação',
  payment_method_id: 'pix',
  external_reference: String(req.user.id),
  payer: {
    email: `${req.user.phone}@mkpainel.com`
  }
})
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('Mercado Pago:', data);
      return res.status(400).json({
        error: 'Não foi possível criar o Pix'
      });
    }

    res.json({
      id: data.id,
      status: data.status,
      qr_code: data.point_of_interaction?.transaction_data?.qr_code,
      qr_code_base64: data.point_of_interaction?.transaction_data?.qr_code_base64
    });
  } catch (error) {
    console.error('Erro Pix:', error);
    res.status(500).json({ error: 'Erro interno ao gerar Pix' });
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
  res.sendFile(
    process.cwd() + '/public/app.html'
  );
});

const PORT = Number(process.env.PORT || 3000);

async function start() {
  try {
    await pool.query('SELECT 1');
    await initDb();
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
