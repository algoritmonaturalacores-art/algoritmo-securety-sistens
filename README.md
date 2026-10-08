# Algoritmo Securety Sistens

Vigilância de entradas e tentativas de acesso para Windows, em consola, sem dependências além do Python.

Nuno Camara | Algoritmo Natural

> **Versão experimental 0.2.0.** Não é antivírus, EDR nem VPN. Complementa o Microsoft Defender; não o substitui.

## O que faz

- **Análise de exposição:** pontuação de 0 a 100 com o que está aberto ou fraco no Windows (acesso remoto, firewall, Defender, contas, UAC, SMB1, Secure Boot, BitLocker) e o que fazer em cada caso.
- **Tentativas de entrada:** lê os registos do Windows à procura de força bruta, RDP externo, contas ou administradores novos, exclusões no antivírus, serviços suspeitos e registo de eventos apagado.
- **Alertas protegidos:** cada alerta fica num registo em cadeia SHA-256; apagar ou alterar uma entrada é detetado. Podes marcar cada alerta como visto, conhecido ou suspeito.
- **Login:** o programa abre com palavra-passe própria (PBKDF2), com bloqueio após tentativas falhadas.
- **Notificações:** aviso no ecrã do Windows; aviso no telemóvel via ntfy é opcional e desligado por omissão.
- **Endurecimento:** lista fechada de alterações ao Windows; cada uma pede confirmação `SIM`. Nada é decidido por IA.
- **Vigilância automática (opcional):** tarefa agendada que corre ao iniciar sessão, a partir de pastas que só administradores podem alterar.
- **Código de 6 dígitos para abrir o Claude (opcional):** com uma app de autenticação (ex.: Ente Auth).

## Requisitos

- Windows 10 ou 11.
- Python 3.10 ou superior, de https://www.python.org/downloads/windows/ (ativar *Add python.exe to PATH*).
- Para a vigilância automática: Python instalado **para todos os utilizadores** (*Install for all users*, fica em `C:\Program Files`) e o programa aberto **como administrador**.

## Instalar

1. Descarrega o ZIP da versão na página **Releases** deste repositório.
2. **Confirma que o ficheiro não foi alterado.** No PowerShell, na pasta do download:
   ```powershell
   Get-FileHash .\algoritmo-securety-sistens-0.2.0.zip -Algorithm SHA256
   ```
   O resultado tem de ser igual ao SHA-256 publicado na Release. Se for diferente, apaga o ficheiro e não o abras.
3. Extrai **todos** os ficheiros para uma pasta.
4. Abre `INICIAR.cmd`. Na primeira vez defines a palavra-passe do programa.
5. Opcional: `INSTALAR.cmd` copia o programa para `%LOCALAPPDATA%` (sem administrador).
6. Opcional: vigilância automática no menu **7**, com o programa aberto como administrador.

Para quem desenvolve: clonar o repositório e correr `python programa.py`. Testes: `python -m unittest discover -s tests -v`.

## O que sai do teu PC

Por omissão, **nada**. Só há ligações à internet se as ligares tu:

| Função | Para onde | O que é enviado |
|---|---|---|
| Aviso no telemóvel (menu 6) | ntfy.sh, ou um servidor HTTPS teu | título e resumo do alerta, nunca palavras-passe |
| Agente IA (menu 10) | API Groq, com a tua chave | o texto exato é mostrado antes e só sai se confirmares; a chave não é guardada |

## Desinstalar

1. Se instalaste a vigilância automática: abre o programa **como administrador**, menu **7** → **2. Remover**. Isto remove a tarefa agendada (e com ela a proteção do Claude) e a cópia em `C:\Program Files\AlgoritmoNatural\SecuretySistens`.
2. Apaga a pasta onde extraíste ou instalaste o programa.
3. Para apagar também os alertas guardados: `C:\ProgramData\AlgoritmoNatural\AlgoritmoSecuretySistens` e `%LOCALAPPDATA%\AlgoritmoSecuretySistens`.

## Limites

- Sem administrador, o registo *Security* do Windows não pode ser lido; algumas deteções ficam indisponíveis.
- Quem já tiver administrador no PC pode desligar a vigilância. O programa deteta e avisa, mas não impede.
- Não procura malware. Usa o Defender ou outro antivírus para isso.
- Não é um executável assinado: corre a partir do código Python, que podes ler antes de usar.

## Reportar uma vulnerabilidade

Em privado, no separador **Security** → **Report a vulnerability**. Não abras issues públicas com detalhes de falhas. Ver [SECURITY.md](SECURITY.md).

## Documentos

- [SECURITY.md](SECURITY.md): o que faz, o que não faz e como reportar falhas.
- [CHANGELOG.md](CHANGELOG.md): alterações por versão.
- [LE-ME-PRIMEIRO.txt](LE-ME-PRIMEIRO.txt): guia rápido, também incluído no ZIP.
- [ARQUITETURA.md](ARQUITETURA.md), [AGENTES-IA.md](AGENTES-IA.md), [INVESTIGACAO.md](INVESTIGACAO.md), [VALIDACAO.md](VALIDACAO.md): desenho e histórico do projeto.

## Licença

MIT. Ver [LICENSE](LICENSE).
