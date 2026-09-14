import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

const JWT = process.env.JWT_SECRET;

if (!JWT) {
  console.error('JWT_SECRET não configurado no Render.');
  process.exit(1);
}

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function sign(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      phone: user.phone
    },
    JWT,
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

    req.user = jwt.verify(header.slice(7), JWT);
    next();
  } catch {
    return res.status(401).json({
      error: 'Sessão inválida'
    });
  }
}

function admin(req, res, next) {
  if (req.user?.role === 'admin') {
    return next();
  }

  return res.status(403).json({
    error: 'Acesso negado'
  });
}

const validLink = (value) =>
  /^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9_-]+$/i.test(
    String(value || '').trim()
  );

async function log(userId, action, details = {}) {
  await pool.query(
    'INSERT INTO audit_logs(user_id,action,details) VALUES($1,$2,$3)',
    [userId, action, details]
  );
}

/*
|--------------------------------------------------------------------------
| CRIA / GARANTE O ADMINISTRADOR
|--------------------------------------------------------------------------
*/

async function ensureAdmin() {
  const phone = normalizePhone(process.env.ADMIN_PHONE);
  const password = String(process.env.ADMIN_PASSWORD || '');

  if (!phone || !password) {
    console.warn(
      'ADMIN_PHONE ou ADMIN_PASSWORD não configurados.'
    );
    return;
  }

  if (password.length < 6) {
    console.warn(
      'ADMIN_PASSWORD precisa ter pelo menos 6 caracteres.'
    );
    return;
  }

  const existing = await pool.query(
    'SELECT * FROM users WHERE phone=$1',
    [phone]
  );

  if (existing.rows[0]) {
    await pool.query(
      'UPDATE users SET role=$1, active=true WHERE phone=$2',
      ['admin', phone]
    );

    console.log('Administrador existente confirmado:', phone);
    return;
  }

  const hash = await bcrypt.hash(password, 12);

  await pool.query(
    'INSERT INTO users(phone,password_hash,role,active) VALUES($1,$2,$3,true)',
    [phone, hash, 'admin']
  );

  console.log('Administrador criado com sucesso:', phone);
}

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get('/api/health', async (_, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(503).json({
      ok: false
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGIN / CRIAÇÃO AUTOMÁTICA DE CLIENTE
|--------------------------------------------------------------------------
*/

app.post('/api/auth/login', async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || '');

    if (!phone) {
      return res.status(400).json({
        error: 'Digite seu telefone.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'A senha precisa ter pelo menos 6 caracteres.'
      });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE phone=$1',
      [phone]
    );

    let user = result.rows[0];

    /*
     * TELEFONE NOVO:
     * cria automaticamente a conta.
     */
    if (!user) {
      const passwordHash = await bcrypt.hash(password, 12);

      const created = await pool.query(
        `INSERT INTO users
        (phone,password_hash,role,active)
        VALUES($1,$2,'user',true)
        RETURNING *`,
        [phone, passwordHash]
      );

      user = created.rows[0];

      console.log('Novo cliente criado:', phone);
    }

    if (!user.active) {
      return res.status(403).json({
        error: 'Esta conta está desativada.'
      });
    }

    /*
     * TELEFONE EXISTENTE:
     * verifica a senha.
     */
    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: 'Telefone ou senha inválidos.'
      });
    }

    res.json({
      token: sign(user),
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
      error: 'Erro interno ao entrar no painel.'
    });
  }
});

/*
|--------------------------------------------------------------------------
| USUÁRIO LOGADO
|--------------------------------------------------------------------------
*/

app.get('/api/me', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,phone,role,balance_cents,active
     FROM users
     WHERE id=$1`,
    [req.user.id]
  );

  if (!result.rows[0]) {
    return res.status(404).json({
      error: 'Usuário não encontrado.'
    });
  }

  res.json(result.rows[0]);
});

/*
|--------------------------------------------------------------------------
| PACOTES
|--------------------------------------------------------------------------
*/

app.get('/api/packages', auth, async (_, res) => {
  const result = await pool.query(
    `SELECT id,name,price_cents,credits
     FROM packages
     WHERE active=true
     ORDER BY price_cents`
  );

  res.json(result.rows);
});

/*
|--------------------------------------------------------------------------
| PIX MERCADO PAGO
|--------------------------------------------------------------------------
*/

app.post('/api/payments/pix', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount_cents);

    if (
      !Number.isInteger(amount) ||
      amount < 3000 ||
      amount > 1000000
    ) {
      return res.status(400).json({
        error: 'Valor inválido. Mínimo R$ 30.'
      });
    }

    if (!process.env.MP_ACCESS_TOKEN) {
      return res.status(503).json({
        error: 'Mercado Pago ainda não configurado no servidor.'
      });
    }

    const external =
      `MK-${req.user.id}-${Date.now()}-${crypto
        .randomBytes(3)
        .toString('hex')}`;

    const idempotency = uuidv4();

    const response = await fetch(
      'https://api.mercadopago.com/v1/payments',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`,
          'Content-Type': 'application/json',
          'X-Idempotency-Key': idempotency
        },
        body: JSON.stringify({
          transaction_amount: amount / 100,
          description: 'Saldo MK Painel Divulgação',
          payment_method_id: 'pix',
          external_reference: external,
          notification_url:
            `${process.env.APP_URL}/api/webhooks/mercadopago`,
          payer: {
            email: req.body.email,
            identification: {
              type: 'CPF',
              number: String(req.body.cpf || '').replace(/\D/g, '')
            }
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: 'Mercado Pago recusou a cobrança.'
      });
    }

    await pool.query(
      `INSERT INTO payments
      (user_id,amount_cents,status,provider_payment_id,
       external_reference,qr_code,qr_code_base64)
      VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [
        req.user.id,
        amount,
        data.status,
        String(data.id),
        external,
        data.point_of_interaction?.transaction_data?.qr_code || null,
        data.point_of_interaction?.transaction_data?.qr_code_base64 || null
      ]
    );

    await log(req.user.id, 'payment.created', {
      payment_id: data.id,
      amount
    });

    res.json({
      id: data.id,
      status: data.status,
      qr_code:
        data.point_of_interaction?.transaction_data?.qr_code,
      qr_code_base64:
        data.point_of_interaction
