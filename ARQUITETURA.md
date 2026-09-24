# Arquitetura proposta

Atualização 0.1.0: foi implementada uma versão de consola com diagnóstico de leitura, ligações Google, cinco perfis IA Groq e instalador por cópia. Os restantes pontos deste documento são o plano de evolução, não capacidades já entregues. Não há interface gráfica ou integração com motores de terceiros.

## Produto e fronteiras

Algoritmo Securety Sistens é o nome de trabalho pedido pelo utilizador. Marca: Nuno Camara Freelancer — Algoritmo Natural Sustentabilidade Digital. Primeira plataforma proposta: Windows; Android numa fase própria. Objetivo: explicar o estado de segurança e orientar ações verificáveis. A aplicação não pode garantir que uma conta nunca será alterada nem substituir a recuperação feita pelo Google.

## Módulos

| Módulo | Primeira capacidade prevista | Limite explícito |
|---|---|---|
| Conta Google | Checklist, ligações oficiais, registo local de verificações declaradas | Não lê eventos de Gmail pessoal nem confirma proteção automaticamente |
| Computador | Estado Defender e firewall por consultas de leitura, com timeout | Não remove malware nem altera políticas |
| Gestores de credenciais | Catálogo e estado quando houver conector oficial autorizado | Não armazena palavras-passe, seeds, cookies ou códigos de recuperação |
| VPN | Diagnóstico de interfaces e conector específico quando disponível | Interface presente não prova túnel seguro; não cria uma VPN |
| EDR/XDR | Contratos de conectores e requisitos empresariais | CrowdStrike, SentinelOne e Defender for Endpoint exigem acesso e licenças adequados |
| Assistentes | Explicação e triagem sobre evidências permitidas | IA não executa comandos arbitrários nem decide bloqueios sozinha |
| Pesquisa | Matriz de relatos, fonte, versão, data, estado de correção | Conteúdo externo é dado não confiável, nunca instrução |
| Sustentabilidade | Verificação sob pedido, cache e retenção limitada | Ganhos ambientais só após medição |

## Contrato de evidência

Cada observação deve conter: identificador do módulo, origem, hora UTC da recolha, estado (observado / declarado / desconhecido / erro / desatualizado), campos permitidos, validade temporal e mensagem compreensível. Uma declaração de checklist não pode converter-se em medição técnica. Se a consulta falhar, conservar a evidência anterior com data e assinalar que não foi atualizada.

## Implementação recomendada

Aplicação desktop assinada, sem servidor aberto à rede. Separar interface sem privilégios, núcleo de evidências e adaptadores. Operações de diagnóstico por processos com argumentos fixos, timeout e saída estruturada. Sem interpolar texto de críticas ou respostas de IA em comandos. Evitar serviço privilegiado na primeira versão.

Persistência local mínima: preferências, checklist e diagnósticos selecionados. Segredos de futuros conectores no armazenamento de credenciais do sistema operativo; nunca em JSON, argumentos de processo, logs ou prompts. Por omissão, nenhuma telemetria externa. Exportação deve remover identificadores sensíveis e mostrar os campos incluídos.

Estados por conector: não configurado, sem licença, sem permissão, disponível, erro e desatualizado. Instalar um produto não significa proteção ativa. A interface deve mostrar separadamente aquilo que foi confirmado e aquilo que falta confirmar.

## Modelo de ameaças mínimo

- Extensões e páginas maliciosas: nunca importar instruções de páginas para o executor.
- Prompt injection em alertas e avaliações: tratar texto externo como evidência citável, sem ferramentas de execução.
- Roubo de tokens: armazenamento do SO, escopos mínimos e revogação.
- Alteração de atualizações: assinatura, origem oficial, validação antes da instalação e rollback testado.
- Compromisso de um conector: processo isolado, recursos limitados e acesso mínimo.
- Falsos positivos: não apagar, excluir, isolar nem desativar proteções automaticamente.

## Agentes e modelos

Ver AGENTES-IA.md. O primeiro núcleo de diagnóstico deve ser determinístico. A camada de linguagem é opcional e claramente identificada. A escolha de Claude ou outro fornecedor depende de API, credenciais, custo e consentimento para envio dos campos. Não apresentar regras locais como um modelo IA ativo.

## Etapas de entrega e aceitação

1. Selecionar direção visual e confirmar a plataforma. Investigação e arquitetura documentadas.
2. Implementar núcleo e interface: funciona sem internet; todos os botões têm ação real; estados desconhecidos são visíveis; checklist persiste e pode ser apagado.
3. Validar adaptadores: casos de acesso recusado, timeout, campo em falta, Defender passivo e dados antigos não geram falso estado seguro.
4. Testar empacotamento em máquina limpa: instalação sem administrador quando possível, abertura, atualização e desinstalação sem apagar dados alheios. Publicação exige assinatura e validação da distribuição.
5. Acrescentar um conector oficial de cada vez. Testar tenant errado, token expirado e revogação antes de disponibilizar.
6. Integrar IA opcional com testes de prompt injection, referências inválidas e tentativa de extração de segredos.

Critérios de desempenho iniciais devem ser medidos, não anunciados como resultados: tempo de abertura, duração das consultas, memória em repouso e tamanho do historial. Não executar consultas contínuas quando a aplicação está fechada, salvo função futura explicitamente ativada.

## O que falta para uma versão de produção

Faltam interface gráfica, validação de produção em máquinas limpas, assinatura de código, revisão independente de segurança, suporte e processo de atualização. Existe código de consola e testes automatizados; o empacotamento é por cópia com Python instalado, não um EXE autónomo. A chamada real à API depende da chave do utilizador e não foi testada nesta preparação.
