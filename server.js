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
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET;

function normalizePhone(value) {
  return String(value || '').replace(/\D/g, '');
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

    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
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
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      balance_cents BIGINT NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS packages (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      price_cents BIGINT NOT NULL,
      credits INTEGER NOT NULL,
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
      completed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      action VARCHAR(100) NOT NULL,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const result = await pool.query(
    'SELECT COUNT(*)::int AS total FROM packages'
  );

  if (result.rows[0].total === 0) {
    await pool.query(`
      INSERT INTO packages
        (name, price_cents, credits)
      VALUES
        ('30 saldo - R$ 30', 3000, 1),
        ('60 saldo - R$ 60', 6000, 2),
        ('100 saldo - R$ 100', 10000, 4)
    `);
  }

  console.log('Banco inicializado.');
}

async function ensureAdmin() {
  const phone = normalizePhone(
    process.env.ADMIN_PHONE
  );

  const password = String(
    process.env.ADMIN_PASSWORD || ''
  );

  if (!phone || !password) {
    return;
  }

  const result = await pool.query(
    'SELECT id FROM users WHERE phone = $1',
    [phone]
  );

  const hash = await bcrypt.hash(
    password,
    12
  );

  if (!result.rows[0]) {
    await pool.query(
      `
      INSERT INTO users
        (phone, password_hash, role, active)
      VALUES
        ($1, $2, 'admin', true)
      `,
      [phone, hash]
    );
  } else {
    await pool.query(
      `
      UPDATE users
      SET password_hash = $1,
          role = 'admin',
          active = true
      WHERE phone = $2
      `,
      [hash, phone]
    );
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
        error: 'Telefone e senha são obrigatórios.'
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
        `
        INSERT INTO users
          (phone, password_hash, role, active)
        VALUES
          ($1, $2, 'user', true)
        RETURNING *
        `,
        [phone, hash]
      );

      user = result.rows[0];
    } else {
      if (!user.active) {
        return res.status(403).json({
          error: 'Sua conta está desativada.'
        });
      }

      const valid = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!valid) {
        return res.status(401).json({
          error: 'Telefone ou senha inválidos.'
        });
      }
    }

    res.json({
      token: createToken(user),
      user: {
        id: user.id,
        phone: user.phone,
        role: user.role,
        balance_cents: user.balance_cents
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Erro interno do servidor.'
    });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, phone, role, balance_cents, active
      FROM users
      WHERE id = $1
      `,
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
      error: 'Erro interno.'
    });
  }
});

app.get('/api/packages', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, price_cents, credits
      FROM packages
      WHERE active = true
      ORDER BY price_cents
      `
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Erro ao carregar pacotes.'
    });
  }
});

app.post('/api/payments/pix', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);

    if (!Number.isFinite(amount) || amount < 30) {
      return res.status(400).json({
        error: 'O valor mínimo é R$ 30,00'
      });
    }

    const amountCents = Math.round(amount * 100);

    const externalReference =
      `MK-${req.user.id}-${crypto.randomUUID()}`;

    const response = await fetch(
      'https://api.mercadopago.com/v1/payments',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization':
            `Bearer ${process.env.MP_ACCESS_TOKEN}`,
          'X-Idempotency-Key':
            crypto.randomUUID()
        },
        body: JSON.stringify({
          transaction_amount: amount,
          description:
            'Crédito MK Painel Divulgação',
          payment_method_id: 'pix',
          external_reference:
            externalReference,
          payer: {
            email:
              req.body.email ||
              `${req.user.phone}@mkpainel.com`
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(
        'Mercado Pago:',
        data
      );

      return res.status(400).json({
        error:
          'Não foi possível criar o Pix.'
      });
    }

    const transaction =
      data.point_of_interaction
        ?.transaction_data;

    await pool.query(
      `
      INSERT INTO payments
      (
        user_id,
        amount_cents,
        status,
        provider,
        provider_payment_id,
        external_reference,
        qr_code,
        qr_code_base64
      )
      VALUES
      ($1, $2, $3, 'mercadopago', $4, $5, $6, $7)
      `,
      [
        req.user.id,
        amountCents,
        data.status || 'pending',
        String(data.id),
        externalReference,
        transaction?.qr_code || null,
        transaction?.qr_code_base64 || null
      ]
    );

    res.json({
      id: data.id,
      status: data.status,
      qr_code:
        transaction?.qr_code || null,
      qr_code_base64:
        transaction?.qr_code_base64 || null
    });
  } catch (error) {
    console.error(
      'Erro Pix:',
      error
    );

    res.status(500).json({
      error:
        'Erro interno ao gerar Pix.'
    });
  }
});

app.post('/api/payments/webhook', async (req, res) => {
  try {
    const paymentId =
      req.body?.data?.id ||
      req.body?.id ||
      req.query['data.id'];

    if (!paymentId) {
      return res.json({ received: true });
    }

    const response = await fetch(
      `https://api.mercadopago.com/v1/payments/${paymentId}`,
      {
        headers: {
          Authorization:
            `Bearer ${process.env.MP_ACCESS_TOKEN}`
        }
      }
    );

    if (!response.ok) {
      return res.json({ received: true });
    }

    const payment = await response.json();

    if (payment.status !== 'approved') {
      return res.json({ received: true });
    }

    const reference =
      String(payment.external_reference || '');

    const result = await pool.query(
      `
      SELECT *
      FROM payments
      WHERE provider_payment_id = $1
         OR external_reference = $2
      LIMIT 1
      `,
      [String(paymentId), reference]
    );

    const saved = result.rows[0];

    if (!saved) {
      return res.json({ received: true });
    }

    if (saved.status === 'approved') {
      return res.json({
        received: true,
        already_processed: true
      });
    }

    const cents = Math.round(
      Number(payment.transaction_amount) * 100
    );

    if (cents !== Number(saved.amount_cents)) {
      return res.json({ received: true });
    }

    await pool.query(
      `
      UPDATE payments
      SET status = 'approved',
          provider_payment_id = $1,
          approved_at = NOW()
      WHERE id = $2
      `,
      [String(paymentId), saved.id]
    );

    await pool.query(
      `
      UPDATE users
      SET balance_cents =
        balance_cents + $1
      WHERE id = $2
      `,
      [cents, saved.user_id]
    );

    await pool.query(
      `
      INSERT INTO audit_logs
        (user_id, action, details)
      VALUES
        ($1, $2, $3)
      `,
      [
        saved.user_id,
        'payment_approved',
        JSON.stringify({
          payment_id: String(paymentId),
          amount_cents: cents
        })
      ]
    );

    console.log(
      `PIX aprovado: ${paymentId}`
    );

    res.json({
      received: true
    });
  } catch (error) {
    console.error(
      'Webhook:',
      error
    );

    res.json({
      received: true
    });
  }
});

app.get('/api/orders', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        o.*,
        p.name AS package_name
      FROM orders o
      JOIN packages p
        ON p.id = o.package_id
      WHERE o.user_id = $1
      ORDER BY o.id DESC
      `,
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

app.post('/api/orders', auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const packageId =
      Number(req.body.package_id);

    const groupLink =
      String(req.body.group_link || '').trim();

    if (!Number.isInteger(packageId)) {
      return res.status(400).json({
        error: 'Pacote inválido.'
      });
    }

    if (!groupLink.startsWith(
      'https://chat.whatsapp.com/'
    )) {
      return res.status(400).json({
        error: 'Link de grupo inválido.'
      });
    }

    await client.query('BEGIN');

    const pkg = await client.query(
      `
      SELECT *
      FROM packages
      WHERE id = $1
        AND active = true
      `,
      [packageId]
    );

    const packageItem = pkg.rows[0];

    if (!packageItem) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Pacote não encontrado.'
      });
    }

    const userResult = await client.query(
      `
      SELECT *
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    );

    const user = userResult.rows[0];

    if (!user) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Usuário não encontrado.'
      });
    }

    if (
      Number(user.balance_cents) <
      Number(packageItem.price_cents)
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Saldo insuficiente.'
      });
    }

    const updated = await client.query(
      `
      UPDATE users
      SET balance_cents =
        balance_cents - $1
      WHERE id = $2
      RETURNING balance_cents
      `,
      [
        packageItem.price_cents,
        req.user.id
      ]
    );

    const order = await client.query(
      `
      INSERT INTO orders
      (
        user_id,
        package_id,
        group_link,
        credits,
        status
      )
      VALUES
      ($1, $2, $3, $4, 'queued')
      RETURNING *
      `,
      [
        req.user.id,
        packageId,
        groupLink,
        packageItem.credits
      ]
    );

    await client.query('COMMIT');

    res.json({
      order: order.rows[0],
      balance_cents:
        updated.rows[0].balance_cents
    });
  } catch (error) {
    await client.query('ROLLBACK');

    console.error(error);

    res.status(500).json({
      error: 'Erro ao criar pedido.'
    });
  } finally {
    client.release();
  }
});

app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        o.*,
        p.name AS package_name
      FROM orders o
      JOIN packages p
        ON p.id = o.package_id
      WHERE o.id = $1
        AND o.user_id = $2
      `,
      [
        req.params.id,
        req.user.id
      ]
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
      error: 'Erro ao carregar pedido.'
    });
  }
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        phone,
        role,
        balance_cents,
        active,
        created_at
      FROM users
      ORDER BY id DESC
      LIMIT 500
      `
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Erro ao carregar usuários.'
    });
  }
});

app.post(
  '/api/admin/users/:id/balance',
  auth,
  admin,
  async (req, res) => {
    try {
      const userId =
        Number(req.params.id);

      const cents =
        Number(req.body.cents);

      if (
        !Number.isInteger(userId) ||
        !Number.isFinite(cents)
      ) {
        return res.status(400).json({
          error: 'Valor inválido.'
        });
      }

      const result = await pool.query(
        `
        UPDATE users
        SET balance_cents =
          GREATEST(
            0,
            balance_cents + $1
          )
        WHERE id = $2
        RETURNING
          id,
          phone,
          balance_cents
        `,
        [
          Math.trunc(cents),
          userId
        ]
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
        error: 'Erro ao atualizar saldo.'
      });
    }
  }
);

app.get('/api/admin/orders', auth, admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        o.id,
        o.group_link,
        o.credits,
        o.status,
        o.created_at,
        u.phone,
        p.name AS package_name,
        p.price_cents
      FROM orders o
      JOIN users u ON u.id = o.user_id
      JOIN packages p ON p.id = o.package_id
      ORDER BY o.id DESC
      LIMIT 100
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Erro ao carregar pedidos.'
    });
  }
});

app.patch('/api/admin/orders/:id/status', auth, admin, async (req, res) => {
  try {
    const allowed = [
      'queued',
      'processing',
      'completed',
      'cancelled'
    ];

    const status = String(req.body.status || '');

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: 'Status inválido.'
      });
    }

    const result = await pool.query(
      `
      UPDATE orders
      SET
        status = $1,
        started_at =
          CASE
            WHEN $1 = 'processing'
              AND started_at IS NULL
            THEN NOW()
            ELSE started_at
          END,
        completed_at =
          CASE
            WHEN $1 = 'completed'
            THEN NOW()
            ELSE completed_at
          END
      WHERE id = $2
      RETURNING *
      `,
      [status, req.params.id]
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
    process.cwd() +
    '/public/app.html'
  );
});

const PORT =
  Number(process.env.PORT || 3000);

async function start() {
  try {
    await pool.query('SELECT 1');
    await initDb();
    await ensureAdmin();

    app.listen(PORT, () => {
      console.log(
        `MK Painel rodando na porta ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      'Erro ao iniciar:',
      error
    );

    process.exit(1);
  }
}

start();
