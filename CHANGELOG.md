# Alterações

## 0.2.0 — vigilância

- Novo: deteção de entradas e tentativas (RDP externo, força bruta, contas/administradores criados, exclusões no antivírus, serviços suspeitos, regras de firewall de entrada, registo de eventos apagado).
- Novo: alertas em cadeia SHA-256, com marcação (visto/ignorado) sem reescrever o histórico.
- Novo: login com palavra-passe (PBKDF2) e bloqueio por tentativas falhadas.
- Novo: notificações toast do Windows e ntfy opcional.
- Novo: endurecimento por lista fechada, com confirmação.
- Novo: tarefa de vigilância protegida (Program Files + ProgramData com ACL).
- Corrigido: bug do `+` em diagnostico.py; string por fechar em endurecer.py.
- Novo: código de 6 dígitos (TOTP, ex.: Ente Auth) para abrir o Claude Code e o Claude Desktop, com códigos de recuperação e bloqueio progressivo.
- Documentação pública: instalação com verificação SHA-256, o que sai do PC e desinstalação completa.
- Licença MIT.

## 0.1.0

- Consola Windows com diagnóstico, ligações de revisão Google e cinco perfis IA (Groq).
