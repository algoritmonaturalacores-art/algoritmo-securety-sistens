# Segurança

Nuno Camara | Algoritmo Natural

## Reportar uma vulnerabilidade

Usar "Report a vulnerability" no separador Security do repositório (aviso privado do GitHub). Não abrir issues públicas com detalhes de falhas. Resposta inicial em até 7 dias.

## O que o programa faz e não faz

- Vigilância só de leitura: lê eventos do Windows e o estado de exposição; não altera nada sozinho.
- Endurecimento: lista fechada de ações, cada uma pede confirmação "SIM" e fica registada. Nenhuma ação é decidida por IA.
- Alertas: registo em cadeia SHA-256 (adulterar ou apagar uma entrada é detetado). Acesso protegido por palavra-passe (PBKDF2) com bloqueio após tentativas falhadas.
- Vigilância permanente: instalada em Program Files/ProgramData com permissões restritas; recusa correr com Python numa pasta do utilizador.
- Notificações: toast do Windows; ntfy é opcional e desligado por omissão (só HTTPS).
- Nenhuma palavra-passe, chave ou token é enviado ou guardado em claro.

## Limites

Não é antivírus, EDR nem VPN certificado. Sem privilégios de administrador o registo Security do Windows não pode ser lido. Um atacante com administrador local pode desativar a vigilância; o programa deteta e avisa, mas não impede.
