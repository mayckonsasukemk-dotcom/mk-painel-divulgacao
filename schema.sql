CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 phone VARCHAR(30) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 balance_cents BIGINT NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
 active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS packages (
 id BIGSERIAL PRIMARY KEY,
 name VARCHAR(100) NOT NULL,
 price_cents BIGINT NOT NULL CHECK(price_cents > 0),
 credits INTEGER NOT NULL CHECK(credits > 0),
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
INSERT INTO packages(name,price_cents,credits) VALUES
('30 saldo - R$ 30',3000,1),('60 saldo - R$ 60',6000,2),('100 saldo - R$ 100',10000,4)
ON CONFLICT DO NOTHING;
