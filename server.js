import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';

const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('sslmode=require')?{rejectUnauthorized:false}:undefined});
app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:process.env.APP_URL||true}));
app.use(express.json({limit:'100kb'}));
app.use(express.static('public'));
const JWT=process.env.JWT_SECRET;
if(!JWT) console.warn('JWT_SECRET ausente');
const sign=u=>jwt.sign({id:u.id,role:u.role,phone:u.phone},JWT,{expiresIn:'7d'});
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Não autenticado'});req.user=jwt.verify(h.slice(7),JWT);next()}catch{return res.status(401).json({error:'Sessão inválida'})}}
const admin=(req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({error:'Acesso negado'});
const validLink=s=>/^https:\/\/chat\.whatsapp\.com\/[A-Za-z0-9_-]+$/i.test(String(s||'').trim());
async function log(userId,action,details={}){await pool.query('INSERT INTO audit_logs(user_id,action,details) VALUES($1,$2,$3)',[userId,action,details])}

app.get('/api/health',async(_,res)=>{try{await pool.query('SELECT 1');res.json({ok:true})}catch(e){res.status(503).json({ok:false})}});
app.post('/api/auth/login',async(req,res)=>{const {phone,password}=req.body;const r=await pool.query('SELECT * FROM users WHERE phone=$1 AND active=true',[phone]);const u=r.rows[0];if(!u||!(await bcrypt.compare(password||'',u.password_hash)))return res.status(401).json({error:'Telefone ou senha inválidos'});res.json({token:sign(u),user:{id:u.id,phone:u.phone,role:u.role,balance_cents:u.balance_cents}})});
app.get('/api/me',auth,async(req,res)=>{const r=await pool.query('SELECT id,phone,role,balance_cents,active FROM users WHERE id=$1',[req.user.id]);res.json(r.rows[0])});
app.get('/api/packages',auth,async(_,res)=>res.json((await pool.query('SELECT id,name,price_cents,credits FROM packages WHERE active=true ORDER BY price_cents')).rows));
app.post('/api/payments/pix',auth,async(req,res)=>{
 const amount=Number(req.body.amount_cents); if(!Number.isInteger(amount)||amount<3000||amount>1000000)return res.status(400).json({error:'Valor inválido. Mínimo R$ 30.'});
 if(!process.env.MP_ACCESS_TOKEN)return res.status(503).json({error:'Mercado Pago ainda não configurado no servidor'});
 const external=`MK-${req.user.id}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
 const idempotency=uuidv4();
 const response=await fetch('https://api.mercadopago.com/v1/payments',{method:'POST',headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,'Content-Type':'application/json','X-Idempotency-Key':idempotency},body:JSON.stringify({transaction_amount:amount/100,description:'Saldo MK Painel Divulgação',payment_method_id:'pix',external_reference:external,notification_url:`${process.env.APP_URL}/api/webhooks/mercadopago`,payer:{email:req.body.email,identification:{type:'CPF',number:String(req.body.cpf).replace(/\D/g,'')}}})});
 const data=await response.json(); if(!response.ok)return res.status(502).json({error:'Mercado Pago recusou a cobrança',detail:data});
 await pool.query('INSERT INTO payments(user_id,amount_cents,status,provider_payment_id,external_reference,qr_code,qr_code_base64) VALUES($1,$2,$3,$4,$5,$6,$7)',[req.user.id,amount,data.status,String(data.id),external,data.point_of_interaction?.transaction_data?.qr_code||null,data.point_of_interaction?.transaction_data?.qr_code_base64||null]);
 await log(req.user.id,'payment.created',{payment_id:data.id,amount});
 res.json({id:data.id,status:data.status,qr_code:data.point_of_interaction?.transaction_data?.qr_code,qr_code_base64:data.point_of_interaction?.transaction_data?.qr_code_base64,external_reference:external});
});
function validSignature(req,paymentId){if(!process.env.MP_WEBHOOK_SECRET)return false;const sig=req.headers['x-signature'];const rid=req.headers['x-request-id'];if(!sig||!rid)return false;const vals=Object.fromEntries(String(sig).split(',').map(x=>x.split('=')));const ts=vals.ts,v1=vals.v1;if(!ts||!v1)return false;const manifest=`id:${paymentId};request-id:${rid};ts:${ts};`;const expected=crypto.createHmac('sha256',process.env.MP_WEBHOOK_SECRET).update(manifest).digest('hex');return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(v1));}
app.post('/api/webhooks/mercadopago',async(req,res)=>{try{const id=req.body?.data?.id;if(!id)return res.sendStatus(200);if(!validSignature(req,id))return res.sendStatus(401);const mp=await fetch(`https://api.mercadopago.com/v1/payments/${id}`,{headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`}});const p=await mp.json();const q=await pool.query('SELECT * FROM payments WHERE provider_payment_id=$1 FOR UPDATE',[String(id)]);const pay=q.rows[0];if(!pay)return res.sendStatus(200);if(p.status==='approved'&&pay.status!=='approved'){await pool.query('BEGIN');try{await pool.query('UPDATE payments SET status=\'approved\',approved_at=NOW() WHERE id=$1',[pay.id]);await pool.query('UPDATE users SET balance_cents=balance_cents+$1 WHERE id=$2',[pay.amount_cents,pay.user_id]);await log(pay.user_id,'payment.approved',{payment_id:id,amount:pay.amount_cents});await pool.query('COMMIT')}catch(e){await pool.query('ROLLBACK');throw e}}else{await pool.query('UPDATE payments SET status=$1 WHERE id=$2',[p.status,pay.id])}res.sendStatus(200)}catch(e){console.error(e);res.sendStatus(500)}});
app.get('/api/payments',auth,async(req,res)=>res.json((await pool.query('SELECT id,amount_cents,status,provider_payment_id,created_at,approved_at FROM payments WHERE user_id=$1 ORDER BY id DESC LIMIT 50',[req.user.id])).rows));
app.post('/api/orders',auth,async(req,res)=>{const {package_id,group_link}=req.body;if(!validLink(group_link))return res.status(400).json({error:'Link de grupo WhatsApp inválido'});const r=await pool.query('SELECT * FROM packages WHERE id=$1 AND active=true',[package_id]);const p=r.rows[0];if(!p)return res.status(404).json({error:'Pacote não encontrado'});const client=await pool.connect();try{await client.query('BEGIN');const u=(await client.query('SELECT balance_cents FROM users WHERE id=$1 FOR UPDATE',[req.user.id])).rows[0];if(u.balance_cents<p.price_cents)throw Object.assign(new Error('Saldo insuficiente'),{status:400});await client.query('UPDATE users SET balance_cents=balance_cents-$1 WHERE id=$2',[p.price_cents,req.user.id]);const o=(await client.query('INSERT INTO orders(user_id,package_id,group_link,credits) VALUES($1,$2,$3,$4) RETURNING *',[req.user.id,p.id,group_link,p.credits])).rows[0];await log(req.user.id,'order.created',{order_id:o.id,credits:p.credits});await client.query('COMMIT');res.json(o)}catch(e){await client.query('ROLLBACK');res.status(e.status||500).json({error:e.message})}finally{client.release()}});
app.get('/api/orders',auth,async(req,res)=>{const sql=req.user.role==='admin'?'SELECT o.*,u.phone,p.name package_name FROM orders o JOIN users u ON u.id=o.user_id JOIN packages p ON p.id=o.package_id ORDER BY o.id DESC LIMIT 200':'SELECT o.*,p.name package_name FROM orders o JOIN packages p ON p.id=o.package_id WHERE o.user_id=$1 ORDER BY o.id DESC LIMIT 100';res.json((await pool.query(sql,req.user.role==='admin'?[]:[req.user.id])).rows)});
app.patch('/api/orders/:id/status',auth,admin,async(req,res)=>{const allowed=['queued','processing','completed','cancelled'];if(!allowed.includes(req.body.status))return res.status(400).json({error:'Status inválido'});const r=await pool.query('UPDATE orders SET status=$1,started_at=CASE WHEN $1=\'processing\' THEN NOW() ELSE started_at END,completed_at=CASE WHEN $1=\'completed\' THEN NOW() ELSE completed_at END WHERE id=$2 RETURNING *',[req.body.status,req.params.id]);res.json(r.rows[0])});
app.get('/api/admin/users',auth,admin,async(_,res)=>res.json((await pool.query('SELECT id,phone,role,balance_cents,active,created_at FROM users ORDER BY id DESC LIMIT 500')).rows));
app.post('/api/admin/users',auth,admin,async(req,res)=>{const {phone,password,role='user'}=req.body;if(!phone||!password||password.length<8)return res.status(400).json({error:'Telefone e senha de no mínimo 8 caracteres são obrigatórios'});const hash=await bcrypt.hash(password,12);try{const r=await pool.query('INSERT INTO users(phone,password_hash,role) VALUES($1,$2,$3) RETURNING id,phone,role,balance_cents',[phone,hash,role==='admin'?'admin':'user']);res.json(r.rows[0])}catch(e){res.status(409).json({error:'Usuário já existe'})}});
app.post('/api/admin/users/:id/balance',auth,admin,async(req,res)=>{const cents=Number(req.body.cents);if(!Number.isInteger(cents))return res.status(400).json({error:'Valor inválido'});const r=await pool.query('UPDATE users SET balance_cents=GREATEST(0,balance_cents+$1) WHERE id=$2 RETURNING id,phone,balance_cents',[cents,req.params.id]);if(!r.rows[0])return res.status(404).json({error:'Usuário não encontrado'});await log(req.user.id,'admin.balance',{target:req.params.id,cents});res.json(r.rows[0])});
app.get('*',(req,res)=>res.sendFile(process.cwd()+'/public/app.html'));
const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`MK Painel rodando na porta ${port}`));
