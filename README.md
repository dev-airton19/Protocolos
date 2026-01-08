# Plataforma de Protocolos Online

Sistema web para gerenciamento de protocolos com autenticação para administradores, servidores e cidadãos.

## 🚀 Deploy no Render

### Pré-requisitos
- Conta no [Render](https://render.com)
- Repositório Git (GitHub, GitLab ou Bitbucket)

### Passos para Deploy

#### 1. Preparar o Repositório
Certifique-se de que seu código está em um repositório Git:
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin <URL_DO_SEU_REPOSITORIO>
git push -u origin main
```

#### 2. Criar o Banco de Dados PostgreSQL no Render

1. Acesse o [Dashboard do Render](https://dashboard.render.com)
2. Clique em **"New +"** → **"PostgreSQL"**
3. Configure:
   - **Name**: `protocolos-db`
   - **Database**: `protocolos_online`
   - **User**: `protocolos_user`
   - **Region**: Escolha a região mais próxima
   - **Plan**: Free (ou outro de sua preferência)
4. Clique em **"Create Database"**
5. **Copie a URL de conexão** (Internal Database URL) - você vai precisar dela

#### 3. Criar o Web Service no Render

1. No Dashboard, clique em **"New +"** → **"Web Service"**
2. Conecte seu repositório Git
3. Configure o serviço:
   - **Name**: `protocolos-online`
   - **Region**: Mesma região do banco de dados
   - **Branch**: `main` (ou sua branch principal)
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

#### 4. Configurar Variáveis de Ambiente

Na seção **"Environment Variables"**, adicione:

- `DATABASE_URL`: Cole a URL do PostgreSQL (copiada no passo 2)
- `SESSION_SECRET`: Clique em "Generate" para criar uma chave segura
- `PORT`: `3001` (ou deixe vazio para usar a porta padrão do Render)
- `NODE_VERSION`: `18`

#### 5. Deploy

1. Clique em **"Create Web Service"**
2. Aguarde o build e deploy (pode levar alguns minutos)
3. Acesse a URL fornecida pelo Render (ex: `https://protocolos-online.onrender.com`)

#### 6. Inicializar o Banco de Dados

Após o primeiro deploy, você precisa criar as tabelas e o usuário admin:

1. Vá para o seu serviço no Render
2. Clique em **"Shell"** (menu lateral)
3. Execute os comandos:

```bash
# Criar as tabelas do banco de dados
npm run db:init

# Criar o primeiro usuário administrador
npm run admin:create
```

Siga as instruções para criar o usuário admin com nome de usuário e senha.

### 📝 Scripts Disponíveis

- `npm start` - Inicia o servidor em produção
- `npm run dev` - Inicia o servidor em modo desenvolvimento
- `npm run db:init` - Inicializa as tabelas do banco de dados
- `npm run admin:create` - Cria um novo usuário administrador
- `npm run servidor:reset-password` - Reseta a senha de um servidor

### 🔒 Segurança

- As senhas são criptografadas com Argon2
- Helmet.js para headers de segurança
- Rate limiting para prevenir ataques de força bruta
- Sessões seguras com PostgreSQL

### 📦 Tecnologias

- **Backend**: Node.js, Express
- **Banco de Dados**: PostgreSQL
- **Autenticação**: Sessions com express-session
- **Segurança**: Helmet, Rate Limiting, Argon2

### 🆘 Troubleshooting

**Erro de conexão com banco de dados:**
- Verifique se a `DATABASE_URL` está correta
- Certifique-se de que o banco de dados está na mesma região do web service

**Aplicação não inicia:**
- Verifique os logs no Dashboard do Render
- Confirme que todas as variáveis de ambiente estão configuradas

**Erro "Table does not exist":**
- Execute `npm run db:init` no Shell do Render para criar as tabelas

### 🌐 Acesso à Aplicação

Após o deploy, acesse:
- **Login Admin**: `https://seu-app.onrender.com/login-admin.html`
- **Login Servidor**: `https://seu-app.onrender.com/login-servidor.html`
- **Cadastro Cidadão**: `https://seu-app.onrender.com/cadastro-cidadao.html`

## 📄 Licença

Este projeto é privado e de uso interno.
