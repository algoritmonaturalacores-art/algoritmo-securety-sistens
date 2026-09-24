# Investigação exploratória — 24/09/2026

Marca: Nuno Camara Freelancer — Algoritmo Natural Sustentabilidade Digital.

Amostra de Google Play, Reddit, GitHub, fóruns de fornecedores e documentação oficial. Não é uma revisão sistemática, um benchmark ou uma conclusão de superioridade. As críticas mostram experiências individuais; não foram reproduzidas. As propostas abaixo são decisões de produto, não correções já implementadas nos fornecedores.

| Produto | Evidência e limites | Requisito para o nosso produto |
|---|---|---|
| Bitwarden | [Google Play](https://play.google.com/store/apps/details?id=com.x8bit.bitwarden): relatos de autofill em 2025. [Comunidade oficial](https://community.bitwarden.com/t/important-android-autofill-updates/87321): alterações e correções Android. | Diagnóstico por versão, navegador e permissões; distinguir erro antigo de problema atual. |
| Bitwarden, extensão | [Issue 17405](https://github.com/bitwarden/clients/issues/17405): pedidos repetidos para atualizar login, encerrada em dezembro de 2025. [Issue 12286](https://github.com/bitwarden/clients/issues/12286): demora ao abrir, aberta no momento da consulta. [Issue 20172](https://github.com/bitwarden/clients/issues/20172): lentidão Chrome, encerrada em junho de 2026. Estado de issue não comprova a situação de todas as versões. | Não deduzir alteração real de uma palavra-passe a partir de um aviso do gestor. Medir latência e evitar verificações em cada interação do navegador. |
| 1Password | [Fórum, discussão de preços em 2026](https://www.1password.community/1password-at-home-31/what-justifies-the-huge-subscription-price-increase-24103). São opiniões de participantes. | Mostrar custos introduzidos pelo utilizador, vencimentos e alternativas de exportação. |
| Dashlane | [Anúncio oficial do fim do plano gratuito](https://www.dashlane.com/blog/dashlane-free-ending). A janela de exportação indicada até 16/09/2026 já passou na data desta pesquisa. | Portabilidade desde o início; avisos claros de mudanças de plano. Não prometer exportação ainda disponível sem confirmar. |
| Bitdefender | [Queixas no fórum sobre publicidade](https://community.bitdefender.com/en/discussion/90437/getting-10000-more-ads-with-bitdefender-than-without). Relatos, não medição da frequência. | Separar risco de marketing; não incluir publicidade no painel inicial. |
| Norton 360 | [Discussão sobre venda adicional](https://community.norton.com/t/norton-upselling/407612). | Alertas agrupados, configuráveis, com motivo e ação úteis. |
| Malwarebytes | [Reddit, março de 2025](https://www.reddit.com/r/Malwarebytes/comments/1jepmwq): bloqueios de jogos relatados. [Procedimento oficial para falsos positivos](https://help.malwarebytes.com/hc/en-us/articles/360038524154-Report-a-false-positive-to-Malwarebytes-Support). | Preservar evidência e encaminhar revisão; nunca criar exclusões amplas automaticamente. |
| Proton VPN | [Google Play](https://play.google.com/store/apps/details?id=ch.protonvpn.android): avaliações consultadas com relatos de ligações presas e sites bloqueados em setembro de 2026. | Distinguir a ligar, ligado, falhou e desconhecido. Site inacessível não prova fuga de dados. |
| NordVPN | [Reddit, junho de 2026](https://www.reddit.com/r/nordvpn/comments/1u85xws/nordvpn_renewal_price_seems_a_bit_high/): crítica ao custo de renovação. [Guia oficial de cancelamento da renovação](https://support.nordvpn.com/hc/en-us/articles/19556844985489-How-to-cancel-auto-renewal-for-your-subscription). | Lembretes opcionais de renovação; não alterar pagamentos automaticamente. |
| ExpressVPN | [Reddit, agosto de 2026](https://www.reddit.com/r/Express_VPN/comments/1vhqu59/vpn_keeps_disconnecting/): desconexões relatadas e não reproduzidas. | Diagnóstico com data e origem; não confundir interface VPN presente com túnel saudável. |
| CrowdStrike | [Análise oficial do incidente de julho de 2024](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf). Incidente histórico, não avaliação de todas as versões atuais. | Atualizações graduais, validação de configuração, rollback; evitar driver kernel próprio no MVP. |
| SentinelOne | [Discussão histórica de 2023](https://www.reddit.com/r/sysadmin/comments/14wxdgw) com experiências contraditórias. [FAQ do fornecedor](https://www.sentinelone.com/faq/). | Evidência por alerta, revisão humana e regras de exceção limitadas. |
| Microsoft Defender for Endpoint | [Documentação de compatibilidade](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility) explica coexistência e modos ativo/passivo. | Coordenar um motor principal; não ativar vários motores por iniciativa do painel. |

## Integrações: o que a documentação permite concluir

- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps): consulta de estado do Defender. Comando indisponível ou recusado deve resultar em desconhecido, nunca em protegido.
- [Bitwarden CLI](https://bitwarden.com/help/cli/) e [APIs Bitwarden](https://bitwarden.com/help/bitwarden-apis/): distinguir estado do cliente, gestão organizacional e acesso ao cofre. Não importar segredos no painel.
- [1Password CLI](https://developer.1password.com/docs/cli/secrets-scripts): integrações precisam de configuração e permissões específicas. Evitar conceder acesso a cofres apenas para mostrar presença do produto.
- [Google Workspace Reports API](https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-login): auditoria de domínio Workspace, com limites documentados; não é um feed equivalente para Gmail pessoal.
- [Consentimento OAuth Google](https://developers.google.com/workspace/guides/configure-oauth-consent): OAuth básico não concede acesso automático ao painel Security Checkup.

## Backlog por prioridade

1. P0: não apresentar estados inventados; diferenciar dados observados, declaração do utilizador e dados desatualizados.
2. P0: roteiro Google e diagnóstico local somente de leitura; ausência de recolha de palavras-passe.
3. P0: isolamento de conectores e falha de um módulo sem bloquear a aplicação.
4. P1: historial local exportável, retenção configurável, agrupamento de alertas.
5. P1: integrações oficiais escolhidas por utilidade e acesso disponível, uma de cada vez.
6. P2: relatórios empresariais EDR/XDR e Workspace com licenças, tenant e consentimento apropriados.
7. P2: medir CPU, memória, latência e consumo de armazenamento antes de afirmar benefícios ambientais.
