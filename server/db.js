import pg from 'pg';

const { Pool } = pg;

export function createPool() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL não configurada. Crie um .env baseado no .env.example');
  }

  return new Pool({
    connectionString,
  });
}
