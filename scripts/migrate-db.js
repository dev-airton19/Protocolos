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
    console.log('🗑️  Removendo tabelas antigas...');
    
    // Remove tabelas antigas
    await client.query('DROP TABLE IF EXISTS servidor_profile CASCADE');
    await client.query('DROP TABLE IF EXISTS servidor_users CASCADE');
    await client.query('DROP TABLE IF EXISTS protocolos CASCADE');
    
    console.log('✅ Tabelas antigas removidas!');
    
    console.log('📦 Criando nova estrutura...');
    
    // Recria tabela de protocolos com estrutura atualizada
    await client.query(`
      CREATE TABLE IF NOT EXISTS protocolos (
        id bigserial PRIMARY KEY,
        
        -- Quem criou o protocolo
        created_by uuid REFERENCES cidadao_users(id) ON DELETE SET NULL,
        created_by_admin uuid REFERENCES admin_users(id) ON DELETE SET NULL,
        created_by_role text NOT NULL CHECK (created_by_role IN ('servidor','admin')),
        
        -- Dados principais (para busca rápida)
        codigo text UNIQUE,
        nome text,
        cpf text,
        natureza text,
        status text NOT NULL DEFAULT 'Enviado',
        
        -- Timestamps
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        
        -- Payload completo do formulário em JSON
        payload jsonb NOT NULL,
        
        -- Constraint: apenas um criador por vez
        CONSTRAINT protocolos_created_by_check CHECK (
          (created_by IS NOT NULL AND created_by_admin IS NULL) OR
          (created_by IS NULL AND created_by_admin IS NOT NULL) OR
          (created_by IS NULL AND created_by_admin IS NULL)
        )
      )
    `);
    
    // Índices para performance
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_created_by ON protocolos (created_by)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_created_by_admin ON protocolos (created_by_admin)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_status ON protocolos (status)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_created_at ON protocolos (created_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_cpf ON protocolos (cpf)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocolos_codigo ON protocolos (codigo)');
    
    console.log('✅ Tabela protocolos criada com sucesso!');
    
    // Verifica estrutura final
    const tables = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);
    
    console.log('\n📋 Tabelas no banco de dados:');
    tables.rows.forEach(row => {
      console.log(`   - ${row.table_name}`);
    });
    
    // Mostra estrutura da tabela protocolos
    const columns = await client.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'protocolos'
      ORDER BY ordinal_position
    `);
    
    console.log('\n📋 Estrutura da tabela protocolos:');
    columns.rows.forEach(row => {
      console.log(`   - ${row.column_name}: ${row.data_type} ${row.is_nullable === 'NO' ? '(NOT NULL)' : ''}`);
    });
    
    console.log('\n✅ Migração concluída com sucesso!');
    
  } catch (e) {
    console.error('❌ Erro:', e.message);
    throw e;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(console.error);
