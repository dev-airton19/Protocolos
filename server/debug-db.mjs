import 'dotenv/config';
import pg from 'pg';

const { Pool } = pg;

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL não está definido no .env');
    process.exit(2);
  }

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const hasAppUsers = await pool.query(
      "select to_regclass('public.app_users') is not null as exists"
    );
    if (hasAppUsers.rows[0]?.exists) {
      const roles = await pool.query(
        "select role, count(*)::int as n from app_users group by role order by role"
      );
      console.log('[legado] app_users ainda existe. roles:', roles.rows);
    } else {
      console.log('[ok] app_users não existe (esperado).');
    }

    const counts = await pool.query(
      `
      select 'servidor_users' as table, count(*)::int as n from servidor_users
      union all
      select 'admin_users' as table, count(*)::int as n from admin_users
      order by table;
      `
    );
    console.log('counts:', counts.rows);

    const protoCounts = await pool.query(
      `
      select
        count(*)::int as total,
        count(created_by_servidor)::int as with_servidor,
        count(created_by_admin)::int as with_admin,
        count(created_by)::int as with_legacy
      from protocolos;
      `
    );
    console.log('protocolos:', protoCounts.rows[0]);
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
