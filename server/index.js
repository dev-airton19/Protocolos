import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Carrega .env da raiz do projeto (um nível acima de server/)
dotenv.config({ path: path.join(__dirname, '..', '.env') });

import os from 'node:os';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import argon2 from 'argon2';
import { createPool } from './db.js';
import { ensureSchemaApplied } from './db-schema.js';
import { hashPassword, isScryptHash, verifyPassword } from './security/passwords.js';

const rootDir = path.resolve(__dirname, '..');

const app = express();
const pool = createPool();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(
  helmet({
    // As páginas usam JS inline; habilitar CSP aqui quebraria sem refatorar para nonce.
    contentSecurityPolicy: false
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const writeLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

const PgSession = connectPgSimple(session);

app.use(
  session({
    store: new PgSession({ pool, tableName: 'session' }),
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: 'auto'
    }
  })
);

if (!process.env.SESSION_SECRET) {
  // eslint-disable-next-line no-console
  console.warn('[AVISO] SESSION_SECRET não definido no .env. Use um valor forte em produção.');
}

function sanitizePlainText(value, maxLen = 500) {
  if (value === null || value === undefined) return value;
  const s = String(value);
  // Remove caracteres de controle + reduz risco de XSS simples em páginas que usam innerHTML
  const cleaned = s
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[<>]/g, '')
    .slice(0, maxLen);
  return cleaned;
}

function isAllowedDataUrl(value) {
  if (typeof value !== 'string') return false;
  // Permite PDF e imagens comuns. (O sistema atual abre anexos em iframe.)
  return /^data:(application\/pdf|image\/(png|jpeg|jpg));base64,/i.test(value);
}

function sanitizeProtocolPayload(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  const cloned = structuredClone(payload);

  const textFields = [
    'codigo',
    'dataCriacao',
    'nome',
    'nascimento',
    'cpf',
    'rg',
    'lotacao',
    'cargo',
    'classe',
    'nivel',
    'admissao',
    'vinculo',
    'situacao',
    'endereco',
    'bairro',
    'municipio',
    'estado',
    'cep',
    'contato',
    'email',
    'natureza',
    'descricaoOutros',
    'inicio',
    'fim',
    'status'
  ];

  for (const k of textFields) {
    if (typeof cloned[k] === 'string') cloned[k] = sanitizePlainText(cloned[k], 500);
  }

  if (Array.isArray(cloned.anexos)) {
    cloned.anexos = cloned.anexos
      .filter((a) => a && typeof a === 'object')
      .map((a) => {
        const out = { ...a };
        if (typeof out.nome === 'string') out.nome = sanitizePlainText(out.nome, 200);
        if (typeof out.origem === 'string') out.origem = sanitizePlainText(out.origem, 30);
        if (typeof out.data === 'string') out.data = sanitizePlainText(out.data, 30);
        if (typeof out.hora === 'string') out.hora = sanitizePlainText(out.hora, 30);

        // base64/data URL: mantém, mas valida formato e limita tamanho para evitar abuso
        if (typeof out.base64 === 'string') {
          if (!isAllowedDataUrl(out.base64)) out.base64 = null;
          if (out.base64 && out.base64.length > 5_000_000) out.base64 = null;
        }
        return out;
      });
  }

  return cloned;
}

function normalizeDigits(value) {
  return String(value ?? '').replace(/\D/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function isValidPassword(password) {
  const v = String(password || '');
  return v.length >= 8 && /[A-Za-z]/.test(v) && /\d/.test(v) && !/\s/.test(v);
}

function toISODateOnly(value) {
  if (!value) return null;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) return value;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function randomUppercaseLetters(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[crypto.randomInt(0, chars.length)];
  return out;
}

function randomDigits(len) {
  let out = '';
  for (let i = 0; i < len; i++) out += String(crypto.randomInt(0, 10));
  return out;
}

function generateProtocolCodeCandidate() {
  // Requisito do usuário:
  // "SEMED" + 3 letras aleatórias + sequência de números aleatórios,
  // podendo ter letras entre esses números, sem traços (tudo junto).
  const prefix = 'SEMED';
  const letters = randomUppercaseLetters(3);
  const digits = randomDigits(10);

  // Às vezes insere uma letra no meio dos números para ficar mais "profissional".
  const insertLetter = crypto.randomInt(0, 2) === 1;
  if (!insertLetter) return `${prefix}${letters}${digits}`;

  const mid = 5; // no meio dos 10 dígitos
  const midLetter = randomUppercaseLetters(1);
  return `${prefix}${letters}${digits.slice(0, mid)}${midLetter}${digits.slice(mid)}`;
}

function legacyProtocolCode({ id, createdAt }) {
  // Fallback para protocolos antigos (antes do código novo existir no payload)
  const year = (() => {
    const d = createdAt ? new Date(createdAt) : new Date();
    return Number.isFinite(d.getTime()) ? d.getFullYear() : new Date().getFullYear();
  })();
  return `SEMED${year}${String(id ?? '').padStart(6, '0')}`;
}

async function generateUniqueProtocolCode(pool) {
  for (let i = 0; i < 12; i++) {
    const candidate = generateProtocolCodeCandidate();
    const exists = await pool.query(
      "select 1 from protocolos where payload->>'codigo' = $1 limit 1",
      [candidate]
    );
    if (!exists.rows.length) return candidate;
  }
  // Extremamente improvável; mas garante que não falha.
  return `${generateProtocolCodeCandidate()}${randomUppercaseLetters(1)}`;
}

function getProtocolCodeFromRow(row) {
  // Primeiro tenta o código direto da coluna
  if (typeof row?.codigo === 'string' && row.codigo.trim() !== '') return row.codigo;
  // Depois tenta do payload
  const fromPayload = row?.payload && typeof row.payload === 'object' ? row.payload.codigo : null;
  if (typeof fromPayload === 'string' && fromPayload.trim() !== '') return fromPayload;
  // Fallback para código legado
  return legacyProtocolCode({ id: row?.id, createdAt: row?.created_at });
}

function requireSession(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({ ok: false, error: 'Não autenticado' });
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session?.user) return res.status(401).json({ ok: false, error: 'Não autenticado' });
    if (req.session.user.role !== role) return res.status(403).json({ ok: false, error: 'Sem permissão' });
    next();
  };
}

function redirectForRole(role) {
  if (role === 'admin') return '/painel-admin.html';
  // Área de suporte (cadastro de admins via web) foi removida; evita loop para páginas protegidas.
  if (role === 'support') return '/login-admin.html';
  return '/painel-servidor.html';
}

function requireRolePage(role, loginPath) {
  return (req, res, next) => {
    if (!req.session?.user) {
      return res.redirect(loginPath);
    }
    if (req.session.user.role !== role) {
      return res.redirect(redirectForRole(req.session.user.role));
    }
    next();
  };
}

function requireAnyRole(roles) {
  const allowed = new Set(roles);
  return (req, res, next) => {
    if (!req.session?.user) return res.status(401).json({ ok: false, error: 'Não autenticado' });
    if (!allowed.has(req.session.user.role)) return res.status(403).json({ ok: false, error: 'Sem permissão' });
    next();
  };
}


app.get('/api/health', async (_req, res) => {
  const r = await pool.query('select 1 as ok');
  res.json({ ok: true, db: r.rows[0].ok });
});

app.get('/api/session', (req, res) => {
  res.json({ ok: true, user: req.session?.user ?? null });
});

async function performLoginWithRole({ role, email, password, req, res }) {
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Campos obrigatórios' });
  
  const normalizedEmail = String(email).toLowerCase();

  // Admin usa admin_users, servidor/cidadão usa cidadao_users
  if (role === 'admin') {
    const result = await pool.query(
      'select id, email, nome, cargo, password from admin_users where email = $1 limit 1',
      [normalizedEmail]
    );

    const user = result.rows[0];
    if (!user || !verifyPassword(user.password, password)) {
      return res.status(401).json({ ok: false, error: 'Credenciais inválidas' });
    }

    // Upgrade transparente: se a senha estiver em texto puro, converte para hash.
    if (user?.password && !isScryptHash(user.password)) {
      const upgraded = hashPassword(password);
      await pool.query('update admin_users set password = $1 where id = $2', [upgraded, user.id]);
    }

    req.session.user = {
      id: user.id,
      role: 'admin',
      email: user.email,
      nome: user.nome,
      cargo: user.cargo
    };

    return res.json({ ok: true });
  }

  // Login de servidor/cidadão usa cidadao_users com argon2
  if (role === 'servidor') {
    const result = await pool.query(
      'select id, email, nome, cpf, telefone, nascimento, password_hash from cidadao_users where email = $1 limit 1',
      [normalizedEmail]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ ok: false, error: 'Credenciais inválidas' });
    }

    // Verifica senha com argon2
    const passwordValid = await argon2.verify(user.password_hash, String(password));
    if (!passwordValid) {
      return res.status(401).json({ ok: false, error: 'Credenciais inválidas' });
    }

    req.session.user = {
      id: user.id,
      role: 'servidor',
      email: user.email,
      nome: user.nome,
      cpf: user.cpf,
      telefone: user.telefone
    };

    return res.json({ ok: true });
  }

  return res.status(400).json({ ok: false, error: 'Role inválida' });
}

// Rotas dedicadas (sem precisar enviar role pelo frontend)
app.post('/api/auth/login/servidor', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  return performLoginWithRole({ role: 'servidor', email, password, req, res });
});

app.post('/api/auth/login/admin', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  return performLoginWithRole({ role: 'admin', email, password, req, res });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { role, email, password } = req.body || {};
  if (!role) return res.status(400).json({ ok: false, error: 'Campos obrigatórios' });
  return performLoginWithRole({ role, email, password, req, res });
});

app.post('/api/auth/guest', authLimiter, async (req, res) => {
  // Guest desabilitado - usuários devem se cadastrar
  return res.status(400).json({ ok: false, error: 'Cadastro de visitante desabilitado. Por favor, crie uma conta.' });
});

app.post('/api/auth/register-cidadao', authLimiter, async (req, res) => {
  const ip = req.ip;
  const body = req.body || {};
  const nome = sanitizePlainText(body.nome, 200);
  const cpfDigits = normalizeDigits(body.cpf);
  const nascimento = toISODateOnly(body.nascimento);
  const email = String(body.email || '').trim().toLowerCase();
  const telefoneDigits = normalizeDigits(body.telefone);
  const password = body.password;
  const aceitaVeracidade = Boolean(body.aceitaVeracidade);
  const aceitaTermos = Boolean(body.aceitaTermos);
  const aceitaPrivacidade = Boolean(body.aceitaPrivacidade);

  const errors = [];
  if (!nome) errors.push('Nome é obrigatório.');
  if (!cpfDigits || cpfDigits.length !== 11) errors.push('CPF inválido.');
  if (!nascimento) errors.push('Data de nascimento é obrigatória.');
  if (!isValidEmail(email)) errors.push('E-mail inválido.');
  if (!telefoneDigits || telefoneDigits.length < 10) errors.push('Telefone inválido.');
  if (!isValidPassword(password)) errors.push('Senha deve ter no mínimo 8 caracteres, com letras, números e sem espaços.');
  if (!aceitaVeracidade || !aceitaTermos || !aceitaPrivacidade) errors.push('É necessário aceitar veracidade, Termos de Uso e Política de Privacidade.');
  if (errors.length) return res.status(400).json({ ok: false, error: errors.join(' ') });

  const now = new Date();
  const passwordHash = await argon2.hash(String(password), {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });

  const client = await pool.connect();
  try {
    await client.query('begin');

    // Verifica duplicidade em cidadao_users
    const dupCidadao = await client.query(
      'select 1 from cidadao_users where cpf = $1 or email = $2 limit 1',
      [cpfDigits, email]
    );
    if (dupCidadao.rowCount) {
      await client.query('rollback');
      return res.status(409).json({ ok: false, error: 'CPF ou e-mail já cadastrado.' });
    }

    // Salva em cidadao_users
    await client.query(
      `insert into cidadao_users (
        nome, cpf, nascimento, email, telefone, password_hash, created_at, created_ip,
        aceita_veracidade, aceita_veracidade_at, aceita_veracidade_ip,
        aceita_termos, aceita_termos_at, aceita_termos_ip,
        aceita_privacidade, aceita_privacidade_at, aceita_privacidade_ip
      ) values (
        $1,$2,$3,$4,$5,$6,$7,$8,
        $9,$10,$11,
        $12,$13,$14,
        $15,$16,$17
      )`,
      [
        nome,
        cpfDigits,
        nascimento,
        email,
        telefoneDigits,
        passwordHash,
        now,
        ip,
        true,
        now,
        ip,
        true,
        now,
        ip,
        true,
        now,
        ip
      ]
    );

    await client.query('commit');
    res.json({ ok: true });
  } catch (e) {
    await client.query('rollback');
    console.error(e);
    res.status(500).json({ ok: false, error: 'Erro ao salvar cadastro.' });
  } finally {
    client.release();
  }
});

// Rota de registro antigo desabilitada - usar register-cidadao
app.post('/api/auth/register', authLimiter, async (req, res) => {
  return res.status(400).json({ ok: false, error: 'Use a página de cadastro de cidadão.' });
});

app.get('/api/servidor/profile', requireRole('servidor'), async (req, res) => {
  const user = req.session.user;

  const r = await pool.query(
    `select
      id,
      email,
      nome,
      cpf,
      nascimento,
      telefone,
      endereco,
      bairro,
      municipio,
      estado,
      cep,
      contato
    from cidadao_users
    where id = $1
    limit 1`,
    [user.id]
  );

  const row = r.rows[0];
  if (!row) return res.status(404).json({ ok: false, error: 'Usuário não encontrado' });

  res.json({
    ok: true,
    profile: {
      nome: row.nome || null,
      email: row.email || null,
      nascimento: toISODateOnly(row.nascimento),
      cpf: row.cpf || null,
      telefone: row.telefone || null,
      endereco: row.endereco || null,
      bairro: row.bairro || null,
      municipio: row.municipio || null,
      estado: row.estado || null,
      cep: row.cep || null,
      contato: row.contato || null,
    }
  });
});

app.post('/api/servidor/protocolos/claim', writeLimiter, requireRole('servidor'), async (req, res) => {
  const user = req.session.user;
  const codigoRaw = req.body?.codigo;
  const codigo = String(codigoRaw ?? '').trim();
  if (!codigo) return res.status(400).json({ ok: false, error: 'Informe o número do protocolo.' });

  const normalized = codigo.replace(/\s+/g, '').toUpperCase();

  // Para segurança: vincula apenas se o CPF do protocolo for igual ao CPF do cidadão.
  const prof = await pool.query('select cpf from cidadao_users where id = $1 limit 1', [user.id]);
  const servidorCpfDigits = normalizeDigits(prof.rows[0]?.cpf);
  if (!servidorCpfDigits) {
    return res.status(400).json({ ok: false, error: 'Seu CPF não está cadastrado no perfil. Atualize seu perfil e tente novamente.' });
  }

  const findById = async (id) => {
    if (!Number.isFinite(id)) return null;
    const r = await pool.query('select id, created_by, created_by_admin, created_by_role, created_at, payload from protocolos where id = $1 limit 1', [id]);
    return r.rows[0] || null;
  };

  const findByCodigo = async (code) => {
    const r = await pool.query("select id, created_by, created_by_admin, created_by_role, created_at, payload from protocolos where payload->>'codigo' = $1 limit 1", [code]);
    return r.rows[0] || null;
  };

  let row = null;

  if (/^\d+$/.test(normalized)) {
    row = await findById(Number(normalized));
  } else if (/^SEMED\d{4}\d{6}$/.test(normalized)) {
    row = await findById(Number(normalized.slice(-6)));
  } else {
    row = await findByCodigo(normalized);
  }

  if (!row) return res.status(404).json({ ok: false, error: 'Protocolo não encontrado.' });

  const payload = row.payload && typeof row.payload === 'object' ? row.payload : {};
  const protocoloCpfDigits = normalizeDigits(payload.cpf);

  if (!protocoloCpfDigits) {
    return res.status(400).json({ ok: false, error: 'Este protocolo não possui CPF no requerimento e não pode ser vinculado automaticamente.' });
  }
  if (protocoloCpfDigits !== servidorCpfDigits) {
    return res.status(403).json({ ok: false, error: 'O CPF do protocolo não confere com o seu CPF cadastrado.' });
  }

  const ownerId = row.created_by;
  if (ownerId && String(ownerId) !== String(user.id)) {
    return res.status(409).json({ ok: false, error: 'Este protocolo já está vinculado a outro servidor.' });
  }

  if (!ownerId) {
    await pool.query('update protocolos set created_by = $1 where id = $2', [user.id, row.id]);
  }

  res.json({ ok: true, id: row.id, codigo: getProtocolCodeFromRow(row) });
});

app.patch('/api/servidor/profile', writeLimiter, requireRole('servidor'), async (req, res) => {
  const user = req.session.user;
  const body = req.body && typeof req.body === 'object' ? req.body : {};

  const client = await pool.connect();
  try {
    await client.query('begin');

    const currentUser = await client.query(
      'select id, email, nome, cpf, nascimento, telefone, endereco, bairro, municipio, estado, cep, contato from cidadao_users where id = $1 limit 1',
      [user.id]
    );
    if (!currentUser.rows.length) {
      await client.query('rollback');
      return res.status(404).json({ ok: false, error: 'Usuário não encontrado' });
    }

    const existing = currentUser.rows[0];

    const nextEmail = (() => {
      if (body.email === undefined || body.email === null) return existing.email;
      const e = String(body.email).trim();
      if (!e) return null;
      return e.toLowerCase();
    })();

    if (!nextEmail) {
      await client.query('rollback');
      return res.status(400).json({ ok: false, error: 'E-mail inválido' });
    }

    const nextNome = body.nome === undefined ? existing.nome : sanitizePlainText(body.nome, 200) || null;
    const nextTelefone = body.telefone === undefined ? existing.telefone : sanitizePlainText(body.telefone, 60) || null;
    const nextEndereco = body.endereco === undefined ? existing.endereco : sanitizePlainText(body.endereco, 300) || null;
    const nextBairro = body.bairro === undefined ? existing.bairro : sanitizePlainText(body.bairro, 100) || null;
    const nextMunicipio = body.municipio === undefined ? existing.municipio : sanitizePlainText(body.municipio, 100) || null;
    const nextEstado = body.estado === undefined ? existing.estado : sanitizePlainText(body.estado, 2) || null;
    const nextCep = body.cep === undefined ? existing.cep : sanitizePlainText(body.cep, 10) || null;
    const nextContato = body.contato === undefined ? existing.contato : sanitizePlainText(body.contato, 20) || null;

    await client.query(
      `update cidadao_users set 
        email = $1, 
        nome = $2, 
        telefone = $3,
        endereco = $4,
        bairro = $5,
        municipio = $6,
        estado = $7,
        cep = $8,
        contato = $9
      where id = $10`,
      [nextEmail, nextNome, nextTelefone, nextEndereco, nextBairro, nextMunicipio, nextEstado, nextCep, nextContato, user.id]
    );

    await client.query('commit');

    req.session.user = { ...req.session.user, email: nextEmail, nome: nextNome };
    res.json({ ok: true });
  } catch (e) {
    try { await client.query('rollback'); } catch { /* ignore */ }
    if (String(e?.code) === '23505') {
      return res.status(409).json({ ok: false, error: 'Email já cadastrado' });
    }
    throw e;
  } finally {
    client.release();
  }
});

// =============================================================================
// ROTAS DO CHAT DE PROTOCOLOS
// =============================================================================

// Buscar mensagens de um protocolo
app.get('/api/protocolos/:id/messages', requireSession, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  const protocoloId = Number(req.params.id);
  if (!Number.isFinite(protocoloId)) {
    return res.status(400).json({ ok: false, error: 'ID de protocolo inválido' });
  }

  // Verifica se o protocolo existe e se o usuário tem acesso
  const protocoloCheck = await pool.query('SELECT id, created_by FROM protocolos WHERE id = $1 LIMIT 1', [protocoloId]);
  if (!protocoloCheck.rows.length) {
    return res.status(404).json({ ok: false, error: 'Protocolo não encontrado' });
  }

  // Servidor só pode ver mensagens dos próprios protocolos
  if (user.role === 'servidor' && String(protocoloCheck.rows[0].created_by) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Sem permissão para acessar este protocolo' });
  }

  // Busca mensagens ordenadas por data
  const result = await pool.query(`
    SELECT 
      id,
      protocolo_id,
      sender_role,
      sender_name,
      message,
      created_at,
      read_at
    FROM protocol_messages
    WHERE protocolo_id = $1
    ORDER BY created_at ASC
  `, [protocoloId]);

  // Marca mensagens como lidas (as que foram enviadas pelo outro papel)
  const otherRole = user.role === 'admin' ? 'servidor' : 'admin';
  await pool.query(`
    UPDATE protocol_messages 
    SET read_at = NOW() 
    WHERE protocolo_id = $1 
    AND sender_role = $2 
    AND read_at IS NULL
  `, [protocoloId, otherRole]);

  res.json({
    ok: true,
    messages: result.rows.map(row => ({
      id: row.id,
      protocoloId: row.protocolo_id,
      senderRole: row.sender_role,
      senderName: row.sender_name,
      message: row.message,
      createdAt: row.created_at,
      readAt: row.read_at
    }))
  });
});

// Enviar mensagem em um protocolo
app.post('/api/protocolos/:id/messages', writeLimiter, requireSession, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  const protocoloId = Number(req.params.id);
  if (!Number.isFinite(protocoloId)) {
    return res.status(400).json({ ok: false, error: 'ID de protocolo inválido' });
  }

  const messageText = sanitizePlainText(req.body?.message, 2000);
  if (!messageText || !messageText.trim()) {
    return res.status(400).json({ ok: false, error: 'Mensagem não pode estar vazia' });
  }

  // Verifica se o protocolo existe e se o usuário tem acesso
  const protocoloCheck = await pool.query('SELECT id, created_by FROM protocolos WHERE id = $1 LIMIT 1', [protocoloId]);
  if (!protocoloCheck.rows.length) {
    return res.status(404).json({ ok: false, error: 'Protocolo não encontrado' });
  }

  // Servidor só pode enviar mensagens nos próprios protocolos
  if (user.role === 'servidor' && String(protocoloCheck.rows[0].created_by) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Sem permissão para acessar este protocolo' });
  }

  // Determina os campos baseado no papel do usuário
  const senderCidadaoId = user.role === 'servidor' ? user.id : null;
  const senderAdminId = user.role === 'admin' ? user.id : null;
  const senderName = user.nome || user.email || 'Usuário';

  const result = await pool.query(`
    INSERT INTO protocol_messages (
      protocolo_id,
      sender_cidadao_id,
      sender_admin_id,
      sender_role,
      sender_name,
      message
    ) VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING id, created_at
  `, [protocoloId, senderCidadaoId, senderAdminId, user.role, senderName, messageText.trim()]);

  const newMessage = result.rows[0];

  res.json({
    ok: true,
    message: {
      id: newMessage.id,
      protocoloId: protocoloId,
      senderRole: user.role,
      senderName: senderName,
      message: messageText.trim(),
      createdAt: newMessage.created_at,
      readAt: null
    }
  });
});

// Contar mensagens não lidas de um protocolo (para badge)
app.get('/api/protocolos/:id/messages/unread-count', requireSession, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  const protocoloId = Number(req.params.id);
  if (!Number.isFinite(protocoloId)) {
    return res.status(400).json({ ok: false, error: 'ID de protocolo inválido' });
  }

  // Conta mensagens não lidas do outro papel
  const otherRole = user.role === 'admin' ? 'servidor' : 'admin';
  const result = await pool.query(`
    SELECT COUNT(*) as count
    FROM protocol_messages
    WHERE protocolo_id = $1 
    AND sender_role = $2 
    AND read_at IS NULL
  `, [protocoloId, otherRole]);

  res.json({
    ok: true,
    unreadCount: parseInt(result.rows[0].count, 10)
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.post('/api/auth/password-reset/request', authLimiter, (_req, res) => {
  // Simulação: em produção você enviaria e-mail.
  res.json({ ok: true });
});

app.get('/painel-admin.html', requireRolePage('admin', '/login-admin.html'), (req, res) => {
  res.sendFile(path.join(rootDir, 'painel-admin.html'));
});

app.get('/painel-servidor.html', requireRolePage('servidor', '/login-servidor.html'), (req, res) => {
  res.sendFile(path.join(rootDir, 'painel-servidor.html'));
});

app.get('/api/protocolos', requireSession, async (req, res) => {
  const user = req.session.user;

  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  // Parâmetros de paginação
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 10));
  const offset = (page - 1) * limit;

  // Contagem total
  const countQuery = user.role === 'admin'
    ? 'SELECT COUNT(*) as total FROM protocolos'
    : 'SELECT COUNT(*) as total FROM protocolos WHERE created_by = $1';
  
  const countResult = user.role === 'admin' 
    ? await pool.query(countQuery) 
    : await pool.query(countQuery, [user.id]);
  
  const total = parseInt(countResult.rows[0].total, 10);
  const totalPages = Math.ceil(total / limit);

  // Busca paginada (ordenado por data de criação, mais recentes primeiro)
  const dataQuery = user.role === 'admin'
    ? `SELECT id, created_by, created_by_admin, created_by_role, nome, cpf, natureza, status, created_at, payload 
       FROM protocolos 
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`
    : `SELECT id, created_by, created_by_admin, created_by_role, nome, cpf, natureza, status, created_at, payload 
       FROM protocolos 
       WHERE created_by = $1 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`;

  const result = user.role === 'admin' 
    ? await pool.query(dataQuery, [limit, offset]) 
    : await pool.query(dataQuery, [user.id, limit, offset]);

  res.json({ 
    ok: true, 
    items: result.rows.map(r => ({
      id: r.id,
      codigo: getProtocolCodeFromRow(r),
      status: r.status,
      nome: r.nome,
      cpf: r.cpf,
      natureza: r.natureza,
      createdAt: r.created_at,
      payload: r.payload
    })),
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  });
});

app.get('/api/protocolos/:id', requireSession, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });

  const result = await pool.query('select * from protocolos where id = $1 limit 1', [id]);
  const row = result.rows[0];
  if (!row) return res.status(404).json({ ok: false, error: 'Não encontrado' });

  const ownerId = row.created_by;
  if (user.role !== 'admin' && String(ownerId) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  res.json({
    ok: true,
    item: {
      id: row.id,
      codigo: getProtocolCodeFromRow(row),
      status: row.status,
      payload: row.payload
    }
  });
});

app.post('/api/protocolos', requireSession, writeLimiter, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'admin' && user.role !== 'servidor') {
      return res.status(403).json({ ok: false, error: 'Sem permissão' });
    }
    const payload = sanitizeProtocolPayload(req.body?.payload);
    if (!payload || typeof payload !== 'object') return res.status(400).json({ ok: false, error: 'payload inválido' });

    const status = payload.status || 'Enviado';

    const codigo = await generateUniqueProtocolCode(pool);
    const payloadWithCode = sanitizeProtocolPayload({ ...payload, codigo });

    const nome = payload.nome ?? null;
    const cpf = payload.cpf ?? null;
    const natureza = payload.natureza ?? null;

    const createdByRole = user.role === 'admin' ? 'admin' : 'servidor';
    const createdBy = createdByRole === 'servidor' ? user.id : null;
    const createdByAdmin = createdByRole === 'admin' ? user.id : null;

    const insert = await pool.query(
      'insert into protocolos (created_by, created_by_admin, created_by_role, codigo, nome, cpf, natureza, status, payload) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id, created_at, payload',
      [createdBy, createdByAdmin, createdByRole, codigo, nome, cpf, natureza, status, payloadWithCode]
    );

    const row = insert.rows[0];
    res.json({ ok: true, id: row.id, codigo: getProtocolCodeFromRow(row) });
  } catch (e) {
    if (String(e?.code) === '23514' && String(e?.constraint) === 'protocolos_created_by_role_check') {
      return res.status(500).json({
        ok: false,
        error: 'Falha de compatibilidade do banco (created_by_role). Rode `npm run db:init` e reinicie o servidor.'
      });
    }
    // eslint-disable-next-line no-console
    console.error('Erro ao salvar protocolo:', e);
    res.status(500).json({ ok: false, error: 'Erro interno ao salvar protocolo' });
  }
});

app.patch('/api/protocolos/:id/status', requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
  if (!status) return res.status(400).json({ ok: false, error: 'status obrigatório' });

  const allowed = new Set(['Enviado', 'Em Análise', 'Deferido', 'Indeferido', 'Concluído']);
  if (!allowed.has(String(status))) {
    return res.status(400).json({ ok: false, error: 'status inválido' });
  }

  const current = await pool.query('select payload from protocolos where id = $1', [id]);
  const row = current.rows[0];
  if (!row) return res.status(404).json({ ok: false, error: 'Não encontrado' });

  const payload = sanitizeProtocolPayload({ ...row.payload, status });

  await pool.query('update protocolos set status = $1, payload = $2 where id = $3', [status, payload, id]);
  res.json({ ok: true });
});

app.post('/api/protocolos/:id/anexos', requireSession, writeLimiter, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }
  const id = Number(req.params.id);
  const { nome, base64, origem } = req.body || {};
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
  if (!nome || !base64 || !origem) return res.status(400).json({ ok: false, error: 'Campos obrigatórios' });

  if (!isAllowedDataUrl(String(base64))) {
    return res.status(400).json({ ok: false, error: 'Formato de anexo não permitido (apenas PDF/PNG/JPG)' });
  }
  if (String(base64).length > 5_000_000) {
    return res.status(400).json({ ok: false, error: 'Anexo muito grande' });
  }

  const current = await pool.query('select created_by, payload from protocolos where id = $1', [id]);
  const row = current.rows[0];
  if (!row) return res.status(404).json({ ok: false, error: 'Não encontrado' });

  const ownerId = row.created_by;
  if (user.role !== 'admin' && String(ownerId) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  const now = new Date();
  const data = now.toLocaleDateString('pt-BR');
  const hora = now.toLocaleTimeString('pt-BR');

  const anexo = {
    id: Date.now(),
    nome: sanitizePlainText(nome, 200),
    data,
    hora,
    base64: String(base64),
    origem: sanitizePlainText(origem, 30)
  };

  const payload = sanitizeProtocolPayload({ ...row.payload });
  const anexos = Array.isArray(payload.anexos) ? payload.anexos : [];
  anexos.push(anexo);
  payload.anexos = anexos;

  await pool.query('update protocolos set payload = $1 where id = $2', [payload, id]);
  res.json({ ok: true, anexoId: anexo.id });
});

app.delete('/api/protocolos/:id/anexos/:anexoId', requireSession, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'admin' && user.role !== 'servidor') {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }
  const id = Number(req.params.id);
  const anexoId = Number(req.params.anexoId);
  if (!Number.isFinite(id) || !Number.isFinite(anexoId)) return res.status(400).json({ ok: false, error: 'Parâmetros inválidos' });

  const current = await pool.query('select created_by, payload from protocolos where id = $1', [id]);
  const row = current.rows[0];
  if (!row) return res.status(404).json({ ok: false, error: 'Não encontrado' });

  const ownerId = row.created_by;
  if (user.role !== 'admin' && String(ownerId) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Sem permissão' });
  }

  const payload = { ...row.payload };
  const anexos = Array.isArray(payload.anexos) ? payload.anexos : [];
  payload.anexos = anexos.filter(a => Number(a.id) !== anexoId);

  await pool.query('update protocolos set payload = $1 where id = $2', [payload, id]);
  res.json({ ok: true });
});

app.delete('/api/protocolos/:id', requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });

  await pool.query('delete from protocolos where id = $1', [id]);
  res.json({ ok: true });
});

app.post('/api/protocolos/test-seed', requireRole('admin'), async (_req, res) => {
  const nomes = [
    'Maria Silva', 'João Santos', 'Ana Costa', 'Carlos Oliveira', 'Paula Ferreira',
    'Pedro Gomes', 'Fernanda Martins', 'Roberto Alves', 'Juliana Rodrigues', 'Felipe Mendes'
  ];

  const naturezas = ['Férias', 'LicencaPremio', 'LicencaMaternidade', 'outros'];
  const cargos = ['Professor', 'Diretor', 'Coordenador', 'Secretário', 'Auxiliar Administrativo'];
  const situacoes = ['Efetivo', 'Prestador', 'Temporario', 'Comissionado'];
  const statusList = ['Enviado', 'Em Análise', 'Deferido', 'Indeferido'];
  const vinculos = ['Estatutario', 'Outros'];

  const insertedIds = [];

  for (let i = 0; i < 10; i++) {
    const payload = {
      nome: nomes[Math.floor(Math.random() * nomes.length)],
      cpf: `${Math.floor(Math.random() * 100000000)}.${Math.floor(Math.random() * 1000)}-${Math.floor(Math.random() * 100)}`,
      rg: `${Math.floor(Math.random() * 10000000)}`,
      nascimento: `${Math.floor(Math.random() * 28) + 1}/${Math.floor(Math.random() * 12) + 1}/${Math.floor(Math.random() * 30) + 1970}`,
      lotacao: 'Escola Municipal de Educação',
      cargo: cargos[Math.floor(Math.random() * cargos.length)],
      classe: `Classe ${String.fromCharCode(65 + Math.floor(Math.random() * 4))}`,
      nivel: `Nível ${Math.floor(Math.random() * 5) + 1}`,
      admissao: `${Math.floor(Math.random() * 28) + 1}/${Math.floor(Math.random() * 12) + 1}/${Math.floor(Math.random() * 20) + 2004}`,
      vinculo: vinculos[Math.floor(Math.random() * vinculos.length)],
      situacao: situacoes[Math.floor(Math.random() * situacoes.length)],
      endereco: `Rua ${Math.floor(Math.random() * 1000)}, nº ${Math.floor(Math.random() * 5000)}`,
      bairro: 'Centro',
      municipio: 'Demerval Lobão',
      cep: `${Math.floor(Math.random() * 100000)}-${Math.floor(Math.random() * 1000)}`,
      contato: `(${Math.floor(Math.random() * 99) + 1}) 9${Math.floor(Math.random() * 100000000)}`,
      email: `servidor${i}@email.com`,
      natureza: naturezas[Math.floor(Math.random() * naturezas.length)],
      descricaoOutros: 'Motivo especial',
      inicio: `${Math.floor(Math.random() * 28) + 1}/${Math.floor(Math.random() * 12) + 1}/2024`,
      fim: `${Math.floor(Math.random() * 28) + 1}/${Math.floor(Math.random() * 12) + 1}/2024`,
      status: statusList[Math.floor(Math.random() * statusList.length)],
      data: new Date().toLocaleDateString('pt-BR'),
      hora: new Date().toLocaleTimeString('pt-BR'),
      anexos: []
    };

    const codigoTest = `SEMED${new Date().getFullYear()}${String(i).padStart(6, '0')}`;
    
    const result = await pool.query(
      'insert into protocolos (created_by_admin, created_by_role, codigo, nome, cpf, natureza, status, payload) values ($1,$2,$3,$4,$5,$6,$7,$8) returning id',
      [null, 'admin', codigoTest, payload.nome ?? null, payload.cpf ?? null, payload.natureza ?? null, payload.status ?? 'Enviado', payload]
    );

    insertedIds.push(result.rows[0].id);
  }

  res.json({ ok: true, inserted: insertedIds.length });
});

app.delete('/api/protocolos', requireRole('admin'), async (_req, res) => {
  await pool.query('delete from protocolos');
  res.json({ ok: true });
});

// Página inicial: manda direto para o login
app.get('/', (req, res) => {
  res.redirect('/login-servidor.html');
});

// Rotas amigáveis para os logins (telas separadas)
app.get('/login/servidor', (_req, res) => {
  res.redirect('/login-servidor.html');
});

app.get('/login/admin', (_req, res) => {
  res.redirect('/login-admin.html');
});

// Mantém compatibilidade com a antiga tela de login (tabs)
app.get(['/portal-autenticacao.html', '/p_6b9f1c2d.html'], (_req, res) => {
  res.redirect('/login-servidor.html');
});

// Servir o site (mesma origem) para cookies funcionarem
// Fica por último para não "furar" a proteção de páginas protegidas.
app.use(express.static(rootDir));

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '0.0.0.0';

function getLanIPv4Addresses() {
  const nets = os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net && net.family === 'IPv4' && !net.internal) out.push(net.address);
    }
  }

  const score = (ip) => {
    if (ip.startsWith('192.168.')) return 3;
    if (ip.startsWith('10.')) return 2;
    if (ip.startsWith('172.')) return 1;
    return 0;
  };

  return [...new Set(out)].sort((a, b) => score(b) - score(a));
}

function logServerUrls(listenPort) {
  // eslint-disable-next-line no-console
  console.log(`Servidor rodando em http://localhost:${listenPort}`);
  const ips = getLanIPv4Addresses();
  if (ips.length) {
    // eslint-disable-next-line no-console
    console.log('Acesso no celular (mesmo Wi‑Fi):');
    for (const ip of ips) {
      // eslint-disable-next-line no-console
      console.log(`- http://${ip}:${listenPort}/`);
    }
  } else {
    // eslint-disable-next-line no-console
    console.log('Não consegui detectar IPs da rede automaticamente. Use `ipconfig` e abra http://SEU_IP:' + listenPort + '/ no celular.');
  }
}

function startServer(initialPort) {
  const maxAttempts = 20;
  const fixedPortRequested = typeof process.env.PORT === 'string' && process.env.PORT.trim() !== '';

  let attemptPort = Number(initialPort);
  let attempts = 0;

  const tryListen = () => {
    attempts += 1;
    const server = app.listen(attemptPort, host, () => logServerUrls(attemptPort));

    server.on('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        if (fixedPortRequested) {
          // eslint-disable-next-line no-console
          console.error(`Porta ${attemptPort} já está em uso. Defina outra em PORT ou finalize o processo que está usando a porta.`);
          process.exit(1);
        }

        if (attempts >= maxAttempts) {
          // eslint-disable-next-line no-console
          console.error('Não encontrei uma porta livre após várias tentativas. Finalize o processo que está usando a porta 3000 ou defina PORT.');
          process.exit(1);
        }

        // eslint-disable-next-line no-console
        console.warn(`Porta ${attemptPort} em uso. Tentando ${attemptPort + 1}...`);
        attemptPort += 1;
        tryListen();
        return;
      }

      // eslint-disable-next-line no-console
      console.error('Erro ao iniciar servidor:', err);
      process.exit(1);
    });
  };

  tryListen();
}

ensureSchemaApplied(pool)
  .then(() => startServer(port))
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Falha ao aplicar schema automaticamente. Rode `npm run db:init` e tente novamente.');
    // eslint-disable-next-line no-console
    console.error(err?.message || err);
    process.exit(1);
  });
