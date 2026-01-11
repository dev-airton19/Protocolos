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
  console.log(`\nUso:\n  npm run servidor:reset-password -- [--email EMAIL | --cpf CPF | --id UUID] [--password SENHA]\n\nNotas:\n- Sem --password, você será solicitado a digitar (oculto) e confirmar.\n- --cpf pode ser digitado com ou sem pontuação.\n- Se houver mais de um servidor com o mesmo CPF, use --id.\n`);
}

function normalizeDigits(value) {
  return String(value ?? '').replace(/\D/g, '');
}

async function promptHidden(query) {
  return await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });

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

async function resolveServidor({ pool, id, email, cpf }) {
  if (id) {
    const r = await pool.query(
      'select id, email, nome, cargo from servidor_users where id = $1 limit 1',
      [String(id)]
    );
    return { rows: r.rows };
  }

  if (email) {
    const normalizedEmail = String(email).toLowerCase();
    const r = await pool.query(
      'select id, email, nome, cargo from servidor_users where email = $1 limit 1',
      [normalizedEmail]
    );
    return { rows: r.rows };
  }

  const cpfDigits = normalizeDigits(cpf);
  if (!cpfDigits) return { rows: [] };

  const r = await pool.query(
    `select u.id, u.email, u.nome, u.cargo
       from servidor_users u
       join servidor_profile p on p.user_id = u.id
      where regexp_replace(coalesce(p.cpf, ''), '\\D', '', 'g') = $1`,
    [cpfDigits]
  );
  return { rows: r.rows };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.h) {
    usage();
    process.exit(0);
  }

  const email = args.email ? String(args.email) : null;
  const id = args.id ? String(args.id) : null;
  const cpf = args.cpf ? String(args.cpf) : null;

  if (!email && !id && !cpf) {
    usage();
    // eslint-disable-next-line no-console
    console.error('Erro: informe --email, --cpf ou --id.');
    process.exit(2);
  }

  let password = args.password ? String(args.password) : null;
  if (!password) {
    const first = await promptHidden('Nova senha do servidor (não aparece): ');
    const second = await promptHidden('Confirmar nova senha: ');
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

    const found = await resolveServidor({ pool, id, email, cpf });
    if (!found.rows.length) {
      // eslint-disable-next-line no-console
      console.error('Servidor não encontrado com os dados informados.');
      process.exit(3);
    }

    if (found.rows.length > 1) {
      // eslint-disable-next-line no-console
      console.error('Mais de um servidor encontrado. Use --id para escolher exatamente qual conta alterar.');
      // eslint-disable-next-line no-console
      console.error('Candidatos:', found.rows.map((r) => ({ id: r.id, email: r.email, nome: r.nome, cargo: r.cargo })));
      process.exit(4);
    }

    const user = found.rows[0];

    const passwordHash = hashPassword(password);
    const updated = await pool.query(
      'update servidor_users set password = $2 where id = $1 returning id, email, nome, cargo',
      [user.id, passwordHash]
    );

    // eslint-disable-next-line no-console
    console.log('Senha redefinida com sucesso para o servidor:', { ...updated.rows[0], role: 'servidor' });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Falha ao redefinir senha do servidor:', e?.message || e);
    process.exit(1);
  } finally {
    await pool.end().catch(() => null);
  }
}

main();
