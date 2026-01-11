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
    console.log('📦 Criando tabela de mensagens do chat...');
    
    // Cria tabela de mensagens
    await client.query(`
      CREATE TABLE IF NOT EXISTS protocol_messages (
        id bigserial PRIMARY KEY,
        
        -- Protocolo relacionado
        protocolo_id bigint NOT NULL REFERENCES protocolos(id) ON DELETE CASCADE,
        
        -- Quem enviou a mensagem (um ou outro)
        sender_cidadao_id uuid REFERENCES cidadao_users(id) ON DELETE SET NULL,
        sender_admin_id uuid REFERENCES admin_users(id) ON DELETE SET NULL,
        
        -- Tipo do remetente para fácil identificação
        sender_role text NOT NULL CHECK (sender_role IN ('servidor', 'admin')),
        
        -- Nome do remetente no momento do envio (para histórico)
        sender_name text NOT NULL,
        
        -- Conteúdo da mensagem
        message text NOT NULL,
        
        -- Timestamps
        created_at timestamptz NOT NULL DEFAULT now(),
        
        -- Se a mensagem foi lida pelo destinatário
        read_at timestamptz,
        
        -- Constraint: apenas um remetente por vez
        CONSTRAINT protocol_messages_sender_check CHECK (
          (sender_cidadao_id IS NOT NULL AND sender_admin_id IS NULL) OR
          (sender_cidadao_id IS NULL AND sender_admin_id IS NOT NULL)
        )
      )
    `);
    console.log('   ✅ Tabela protocol_messages criada');

    // Cria índices
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocol_messages_protocolo ON protocol_messages (protocolo_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocol_messages_created_at ON protocol_messages (created_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocol_messages_sender_cidadao ON protocol_messages (sender_cidadao_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_protocol_messages_sender_admin ON protocol_messages (sender_admin_id)');
    console.log('   ✅ Índices criados');

    // Mostra estrutura
    const result = await client.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'protocol_messages'
      ORDER BY ordinal_position
    `);

    console.log('\n📋 Estrutura da tabela protocol_messages:');
    result.rows.forEach(row => {
      console.log(`   - ${row.column_name}: ${row.data_type} ${row.is_nullable === 'NO' ? '(NOT NULL)' : ''}`);
    });

    console.log('\n✅ Migração do chat concluída com sucesso!');
    
  } catch (err) {
    console.error('❌ Erro durante a migração:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
