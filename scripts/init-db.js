import 'dotenv/config';
import pg from 'pg';
import { ensureSchemaApplied } from './db-schema.js';

const { Pool } = pg;

function parseDatabaseUrl(url) {
  try {
    const u = new URL(url);
    const dbName = u.pathname?.replace(/^\//, '') || '';
    return { url: u, dbName };
  } catch {
    return null;
  }
}

async function ensureDatabaseExists(databaseUrl) {
  const parsed = parseDatabaseUrl(databaseUrl);
  if (!parsed) throw new Error('DATABASE_URL inválida');
  if (!parsed.dbName) throw new Error('DATABASE_URL sem nome do banco no final');

  const adminUrl = new URL(parsed.url.toString());
  adminUrl.pathname = '/postgres';

  const adminPool = new Pool({ connectionString: adminUrl.toString() });
  try {
    const safeDbName = String(parsed.dbName).replace(/"/g, '""');
    await adminPool.query(`CREATE DATABASE "${safeDbName}"`);
  } catch (e) {
    // 42P04 = duplicate_database
    if (String(e?.code) !== '42P04') throw e;
  } finally {
    await adminPool.end();
  }
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error('DATABASE_URL não configurada. Crie um .env baseado no .env.example');
  }

  await ensureDatabaseExists(databaseUrl);

  const pool = new Pool({ connectionString: databaseUrl });
  try {
    await ensureSchemaApplied(pool);
  } finally {
    await pool.end();
  }

  // eslint-disable-next-line no-console
  console.log('Banco inicializado e schema aplicado com sucesso.');
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('Falha ao inicializar banco:', e?.message || e);
  process.exitCode = 1;
});
