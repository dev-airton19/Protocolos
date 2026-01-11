module.exports = {
  apps: [
    {
      name: 'protocolos',
      script: './server/index.js',
      instances: 'max',
      exec_mode: 'cluster',
      
      // Variáveis de ambiente
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      
      // Configurações de log
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: './logs/error.log',
      out_file: './logs/output.log',
      log_file: './logs/combined.log',
      
      // Limite de memória
      max_memory_restart: '500M',
      
      // Configurações de restart
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s',
      
      // Configurações de watch (desabilitado em produção)
      watch: false,
      ignore_watch: ['node_modules', 'logs', '.git'],
      
      // Configurações de cluster
      wait_ready: true,
      listen_timeout: 10000,
      kill_timeout: 5000,
      
      // Graceful shutdown
      shutdown_with_message: true
    }
  ],
  
  // Configurações de deploy (opcional)
  deploy: {
    production: {
      user: 'seu-usuario',
      host: 'srv1257617.hstgr.cloud',
      ref: 'origin/main',
      repo: 'seu-repositorio-git.git',
      path: '~/protocolos',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
