import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function ensureSchemaApplied(pool) {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = await fs.readFile(schemaPath, 'utf8');

  // Aplica o schema (tabelas e índices)
  await pool.query(sql);

  // Verifica se as tabelas principais existem
  const tablesCheck = await pool.query(`
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
    AND table_name IN ('cidadao_users', 'admin_users', 'protocolos', 'session')
  `);

  const existingTables = tablesCheck.rows.map(r => r.table_name);
  const requiredTables = ['cidadao_users', 'admin_users', 'protocolos', 'session'];
  
  for (const table of requiredTables) {
    if (!existingTables.includes(table)) {
      throw new Error(`Tabela obrigatória '${table}' não foi criada. Verifique o schema.sql.`);
    }
  }
}
