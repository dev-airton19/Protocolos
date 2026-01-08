-- =============================================================================
-- SCHEMA DO SISTEMA DE PROTOCOLOS - SEMED
-- Versão: 2.0 (Janeiro 2025)
-- =============================================================================

-- Extensões
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- TABELA: admin_users
-- Administradores do sistema
-- =============================================================================
CREATE TABLE IF NOT EXISTS admin_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password text NOT NULL,
  nome text,
  cargo text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- TABELA: cidadao_users
-- Usuários cidadãos/servidores que fazem login no sistema
-- Esta é a tabela principal de autenticação
-- =============================================================================
CREATE TABLE IF NOT EXISTS cidadao_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nome text NOT NULL,
  cpf text NOT NULL UNIQUE,
  nascimento date NOT NULL,
  email text NOT NULL UNIQUE,
  telefone text NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_ip inet NOT NULL,

  -- Campos de endereço
  endereco text,
  bairro text,
  municipio text,
  estado text,
  cep text,
  contato text,

  -- Consentimentos LGPD
  aceita_veracidade boolean NOT NULL,
  aceita_veracidade_at timestamptz NOT NULL,
  aceita_veracidade_ip inet NOT NULL,
  aceita_termos boolean NOT NULL,
  aceita_termos_at timestamptz NOT NULL,
  aceita_termos_ip inet NOT NULL,
  aceita_privacidade boolean NOT NULL,
  aceita_privacidade_at timestamptz NOT NULL,
  aceita_privacidade_ip inet NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cidadao_users_email ON cidadao_users (email);
CREATE INDEX IF NOT EXISTS idx_cidadao_users_cpf ON cidadao_users (cpf);

-- =============================================================================
-- TABELA: protocolos
-- Protocolos/Requerimentos dos servidores
-- =============================================================================
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
  -- Campos do payload:
  --   dataCriacao, nome, nascimento, cpf, rg, localTrabalho, cargo,
  --   classe (só professor efetivo), nivel (só professor efetivo),
  --   admissao, vinculo, situacao, cep, endereco, bairro, municipio,
  --   estado, contato, email, natureza, descricaoOutros, inicio, fim,
  --   anexos[], status
  payload jsonb NOT NULL,
  
  -- Constraint: apenas um criador por vez
  CONSTRAINT protocolos_created_by_check CHECK (
    (created_by IS NOT NULL AND created_by_admin IS NULL) OR
    (created_by IS NULL AND created_by_admin IS NOT NULL) OR
    (created_by IS NULL AND created_by_admin IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_protocolos_created_by ON protocolos (created_by);
CREATE INDEX IF NOT EXISTS idx_protocolos_created_by_admin ON protocolos (created_by_admin);
CREATE INDEX IF NOT EXISTS idx_protocolos_status ON protocolos (status);
CREATE INDEX IF NOT EXISTS idx_protocolos_created_at ON protocolos (created_at);
CREATE INDEX IF NOT EXISTS idx_protocolos_cpf ON protocolos (cpf);
CREATE INDEX IF NOT EXISTS idx_protocolos_codigo ON protocolos (codigo);

-- =============================================================================
-- TABELA: protocol_messages
-- Mensagens de chat entre servidores e administradores em cada protocolo
-- =============================================================================
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
);

CREATE INDEX IF NOT EXISTS idx_protocol_messages_protocolo ON protocol_messages (protocolo_id);
CREATE INDEX IF NOT EXISTS idx_protocol_messages_created_at ON protocol_messages (created_at);
CREATE INDEX IF NOT EXISTS idx_protocol_messages_sender_cidadao ON protocol_messages (sender_cidadao_id);
CREATE INDEX IF NOT EXISTS idx_protocol_messages_sender_admin ON protocol_messages (sender_admin_id);

-- =============================================================================
-- TABELA: session
-- Sessões do express-session (connect-pg-simple)
-- =============================================================================
CREATE TABLE IF NOT EXISTS session (
  sid varchar NOT NULL COLLATE "default",
  sess json NOT NULL,
  expire timestamptz NOT NULL,
  PRIMARY KEY (sid)
);

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON session (expire);

-- =============================================================================
-- NOTAS:
-- 
-- Cargos disponíveis no formulário:
--   - Professor efetivo (com classe e nível)
--   - Auxiliar de Serviços gerais
--   - Professor temporário
--   - Auxiliar técnico pedagógico
--   - Vigia
--   - Cargo comissionado
--   - Outros (campo texto livre)
--
-- Naturezas de requerimento:
--   - Ferias
--   - LicencaPremio
--   - LicencaMaternidade
--   - outros (com descrição)
--
-- Status possíveis:
--   - Enviado
--   - Em análise
--   - Deferido
--   - Indeferido
--   - Arquivado
-- =============================================================================
