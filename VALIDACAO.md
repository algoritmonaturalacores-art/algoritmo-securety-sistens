# Validação da versão 0.1.0

Executado em Windows com Python 3.14.7, em 24/09/2026.

- `python -m unittest discover -s tests -v`: 17 testes passaram.
- `python programa.py --verificar`: estrutura validada; cinco agentes definidos.
- Instalação por cópia testada numa pasta temporária, incluindo recusa de sobrescrita e preservação de ficheiros existentes.
- API testada com respostas simuladas: sucesso, quota esgotada, timeout, formato inválido, chave inválida, bloqueio de redirecionamento e remoção de caracteres de controlo.
- Cancelar o envio no menu não efetua chamada API.
- Diagnóstico executado neste ambiente: Defender e firewall ficaram como indisponíveis (consulta falhada ou timeout). O programa conservou o estado não verificado; não foi possível confirmar a proteção deste computador.

Não foi efetuada uma chamada real à Groq: necessita de uma chave do utilizador. Não há validação de qualidade das respostas reais, certificação de segurança, instalador EXE assinado ou ensaio de produção em máquina limpa. Python 3.10–3.13 não foram ensaiados nesta sessão.
