# Algoritmo Securety Sistens

Nuno Camara Freelancer — Algoritmo Natural Sustentabilidade Digital

Estado: versão experimental 0.1.0 para consola Windows, 24/09/2026. Inclui código executável Python, lançador, instalação por cópia e cinco perfis IA através da API Groq. Não é um antivírus, VPN ou EDR certificado.

## Abrir o programa

Usar esta pasta completa, instalar Python 3.10+ se necessário e abrir `INICIAR.cmd`. Se receber uma cópia em ZIP, extrair primeiro todos os ficheiros. Para copiar para uma pasta permanente, abrir `INSTALAR.cmd`. Ler `LE-ME-PRIMEIRO.txt` para os passos completos. O pacote não é um EXE autónomo ou assinado.

O menu permite consultar o Defender e perfis firewall, obter ligações oficiais para revisão Google e consultar um dos cinco agentes. A IA necessita de uma chave da tua conta Groq no plano Free. Nenhuma chave é fornecida ou guardada. O plano gratuito tem quotas; a aplicação não verifica a faturação da conta nem garante custo zero com uma chave de plano pago. Consulte https://console.groq.com/docs/rate-limits.

## Objetivo

Criar um centro modular de segurança que ajude a rever contas Google, consultar o estado do computador e coordenar ferramentas existentes. Windows é a hipótese inicial, a confirmar pelo utilizador. Android exige uma aplicação e permissões próprias.

## Documentos

- INVESTIGACAO.md: amostra de críticas públicas e requisitos derivados.
- ARQUITETURA.md: módulos, limites, segurança e critérios de aceitação.
- AGENTES-IA.md: desenho dos agentes e estado da implementação.
- LE-ME-PRIMEIRO.txt: utilização e configuração da API gratuita.
- programa.py e seguranca/: código da versão de consola, sem dependências externas ao Python.
- tests/: testes locais e de API simulada.

## Prioridade imediata: contas Google

Alterações desconhecidas precisam de verificação; não demonstram por si só que alguém entrou na conta. Num dispositivo de confiança, seguir o guia oficial https://support.google.com/accounts/answer/6294825 para rever eventos recentes, dispositivos, recuperação e verificação em dois passos. Se o acesso se perdeu, usar o processo oficial de recuperação. Não introduzir palavras-passe, códigos de recuperação ou tokens neste projeto.

## Limites da primeira entrega

Esta pasta contém um assistente experimental de consola, sem interface gráfica, monitorização contínua ou remediação. Os agentes são perfis consultivos no mesmo modelo, não sistemas autónomos com acesso às contas. A pesquisa é exploratória e não abrange todos os marketplaces. Os produtos referidos são marcas dos respetivos titulares; não existe afiliação nem redistribuição dos seus motores. Não foi criado um repositório público nem publicada informação de contas. A API real ainda precisa de validação com uma chave do utilizador; os testes usam respostas simuladas.
