import 'dotenv/config';
import readline from 'node:readline';
import { createPool } from './db.js';
import { ensureSchemaApplied } from './db-schema.js';
import { hashPassword } from './security/passwords.js';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;

    const eq = a.indexOf('=');
    const key = (eq >= 0 ? a.slice(2, eq) : a.slice(2)).trim();
    if (key === 'force') {
      args.force = true;
      continue;
    }

    if (eq >= 0) {
      args[key] = a.slice(eq + 1);
      continue;
    }

    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      args[key] = true;
      continue;
    }

    // Permite valores com espaços sem precisar de aspas, ex: --nome Mariana Leticia
    // Junta tokens até o próximo argumento que comece com "--".
    const parts = [value];
    let j = i + 2;
    while (j < argv.length && !String(argv[j]).startsWith('--')) {
      parts.push(argv[j]);
      j++;
    }
    args[key] = parts.join(' ');
    i = j - 1;
  }
  return args;
}

function usage() {
  // eslint-disable-next-line no-console
  console.log(`\nUso:\n  npm run admin:create -- --email EMAIL [--nome NOME] [--cargo CARGO] [--password SENHA] [--force]\n\nNotas:\n- --nome e --cargo aceitam múltiplas palavras sem aspas (ex.: --nome Mariana Leticia).\n- Você também pode usar --nome="Mariana Leticia" (opcional).\n- Sem --password, você será solicitado a digitar (oculto).\n- Sem --force, não altera usuário existente com o mesmo email.\n`);
}

async function promptHidden(query) {
  return await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });

    // Oculta caracteres digitados e mostra apenas '*'
    rl.stdoutMuted = true;
    // eslint-disable-next-line no-underscore-dangle
    rl._writeToOutput = function _writeToOutput(stringToWrite) {
      if (this.stdoutMuted) {
        if (stringToWrite.trim() !== '') this.output.write('*');
        return;
      }
      this.output.write(stringToWrite);
    };

    rl.question(query, (value) => {
      rl.close();
      process.stdout.write('\n');
      resolve(value);
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.h) {
    usage();
    process.exit(0);
  }

  const email = args.email ? String(args.email).toLowerCase() : null;
  const nome = args.nome ? String(args.nome) : 'Administrador';
  const cargo = args.cargo ? String(args.cargo) : 'Administrador do Sistema';

  if (!email) {
    usage();
    // eslint-disable-next-line no-console
    console.error('Erro: --email é obrigatório.');
    process.exit(2);
  }

  let password = args.password ? String(args.password) : null;
  if (!password) {
    const first = await promptHidden('Senha do admin (não aparece): ');
    const second = await promptHidden('Confirmar senha: ');
    if (first !== second) {
      // eslint-disable-next-line no-console
      console.error('Erro: as senhas não conferem.');
      process.exit(2);
    }
    password = first;
  }

  if (!password || String(password).trim().length < 4) {
    // eslint-disable-next-line no-console
    console.error('Erro: senha muito curta (mínimo 4 caracteres).');
    process.exit(2);
  }

  const pool = createPool();

  try {
    await ensureSchemaApplied(pool);

    // Garante unicidade global de email entre tabelas (mais seguro/consistente)
    const existsServidor = await pool.query('select id from cidadao_users where email = $1 limit 1', [email]);
    if (existsServidor.rows[0]) {
      // eslint-disable-next-line no-console
      console.error('Já existe um servidor com este email. Use outro email para o admin.');
      process.exit(3);
    }

    const existing = await pool.query('select id, email from admin_users where email = $1 limit 1', [email]);
    const row = existing.rows[0];

    const passwordHash = hashPassword(password);

    if (row) {
      if (!args.force) {
        // eslint-disable-next-line no-console
        console.error(`Já existe um admin com este email (id=${row.id}). Para atualizar senha/nome, use --force.`);
        process.exit(3);
      }

      const updated = await pool.query(
        'update admin_users set password = $2, nome = $3, cargo = $4 where id = $1 returning id, email',
        [row.id, passwordHash, nome, cargo]
      );

      // eslint-disable-next-line no-console
      console.log('Admin atualizado com sucesso:', { ...updated.rows[0], role: 'admin' });
      return;
    }

    const inserted = await pool.query(
      "insert into admin_users (email, password, nome, cargo) values ($1, $2, $3, $4) returning id, email",
      [email, passwordHash, nome, cargo]
    );

    // eslint-disable-next-line no-console
    console.log('Admin criado com sucesso:', { ...inserted.rows[0], role: 'admin' });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Falha ao criar admin:', e?.message || e);
    process.exit(1);
  } finally {
    await pool.end().catch(() => null);
  }
}

main();
