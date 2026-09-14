# MK Painel Divulgação — versão real

## O que já está implementado
- Login seguro com senha hash bcrypt.
- Banco PostgreSQL.
- Saldo persistente.
- Pacotes de saldo.
- Pix Mercado Pago via API.
- Idempotência no pagamento.
- Webhook Mercado Pago com validação de assinatura.
- Crédito automático após pagamento aprovado.
- Pedidos de divulgação e fila.
- Painel administrativo para criar usuários e ajustar saldo.
- HTTPS deve ser fornecido pelo host/reverse proxy.

## Importante sobre a divulgação
O sistema registra e organiza links enviados pelos clientes. A execução deve usar somente grupos/canais parceiros ou autorizados. Não há função para adicionar pessoas sem consentimento, disparar spam ou inventar uma base de grupos.

## Configuração
1. Crie PostgreSQL e rode `sql/schema.sql`.
2. Copie `.env.example` para `.env` e preencha as credenciais.
3. `npm install` e `npm start`.
4. Cadastre/configure o webhook de produção no Mercado Pago apontando para `/api/webhooks/mercadopago`.
5. Use domínio HTTPS e nunca publique o `.env`.
6. Troque `ADMIN_PASSWORD` e o `JWT_SECRET` antes da produção.

O Access Token do Mercado Pago deve ficar apenas no servidor. O Mercado Pago exige HTTPS para chamadas de API e recomenda manter credenciais privadas fora do frontend. Webhooks devem ser validados antes de processar pagamentos.
