import pg from 'pg';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function main() {
  const client = await pool.connect();
  
  try {
    console.log('📦 Adicionando colunas de endereço na tabela cidadao_users...');
    
    // Adiciona colunas de endereço se não existirem
    const columns = [
      { name: 'endereco', type: 'text' },
      { name: 'bairro', type: 'text' },
      { name: 'municipio', type: 'text' },
      { name: 'estado', type: 'text' },
      { name: 'cep', type: 'text' },
      { name: 'contato', type: 'text' }
    ];

    for (const col of columns) {
      // Verifica se a coluna já existe
      const check = await client.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'cidadao_users' 
        AND column_name = $1
      `, [col.name]);

      if (check.rows.length === 0) {
        await client.query(`ALTER TABLE cidadao_users ADD COLUMN ${col.name} ${col.type}`);
        console.log(`   ✅ Coluna '${col.name}' adicionada`);
      } else {
        console.log(`   ⏭️  Coluna '${col.name}' já existe`);
      }
    }

    // Mostra estrutura atualizada
    const result = await client.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'cidadao_users'
      ORDER BY ordinal_position
    `);

    console.log('\n📋 Estrutura atualizada da tabela cidadao_users:');
    result.rows.forEach(row => {
      console.log(`   - ${row.column_name}: ${row.data_type} ${row.is_nullable === 'NO' ? '(NOT NULL)' : ''}`);
    });

    console.log('\n✅ Migração concluída com sucesso!');
    
  } catch (err) {
    console.error('❌ Erro durante a migração:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
