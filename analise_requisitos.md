## Objetivo - Criar uma ferramenta de limpeza profunda para Windows para limpeza e melhoria de desempenho

A ferramenta **Clean Cache** varrerá os discos e SSDs do sistema operacional Windows (como pastas `%TEMP%`), realizará a limpeza de arquivos duplicados e atuará como uma ferramenta de antivírus usando IA generativa para identificar possíveis ameaças que já podem estar sendo executadas.

## Levantamento de Bibliotecas

### Bibliotecas para Antivírus
- `yara-python` (Requer Microsoft C++ Build Tools para instalação no Windows para versões acima de 3.14)
- `pefile`
- `hashlib`
- `volatility3`
- `pycdlib`

### Monitoramento de sistemas de arquivos e utilitários

Cada biblioteca desempenha um papel específico na orquestração do sistema:

- `watchdog`: Monitoramento em tempo real de eventos do sistema de arquivos (criação, modificação de arquivos).
- `psutil`: Gerenciamento e monitoramento de processos ativos e uso de recursos do sistema (CPU, Memória).
- `os`, `sys`: Interação direta com o sistema operacional para manipulação de arquivos, diretórios e variáveis de ambiente.
- `requests`: Comunicação via rede para integração com APIs externas (ex: VirusTotal) e atualizações.
- `scikit-learn`: Implementação de algoritmos de Machine Learning para classificação de ameaças e detecção de anomalias.
- `FreeSimpleGUI`: Criação da interface gráfica (GUI) para interação com o usuário.
- `Matplotlib`: Renderização de gráficos estatísticos na interface.

## Fluxo de Antivírus (Pipeline Sincronizado)

A sincronização das bibliotecas cria camadas de defesa complementares:

1. **Triagem Rápida (Identidade)**:
   - `watchdog`: Detecta a chegada do arquivo em tempo real.
   - `hashlib`: Gera o hash (SHA256) para consulta rápida em bases de dados (VirusTotal).

2. **Análise Estática (Estrutura e Padrões)**:
   - `pefile`: Analisa a estrutura do executável (cabeçalhos, seções suspeitas) antes de qualquer execução.
   - `yara-python`: Varre o conteúdo binário em busca de assinaturas de malware (regras customizadas).

3. **Análise Forense (Memória)**:
   - `volatility3`: Atua em varreduras profundas para identificar ameaças ocultas na memória RAM (rootkits ou malwares *fileless*).

4. **Ação**:
   - `os`/`shutil`: Move para quarentena ou remove o arquivo baseado na pontuação de risco acumulada das etapas anteriores.

## Arquitetura do Projeto

A aplicação é dividida em três módulos principais para separar responsabilidades:

- **`main.py` (Motor)**: Ponto de entrada da aplicação. Gerencia a inicialização e conecta o cérebro à interface.
- **`brain.py` (Cérebro)**: Contém a lógica pesada. Gerencia as bibliotecas de segurança (`yara`, `pefile`, etc.), monitoramento (`watchdog`) e limpeza.
- **`interface.py` (UX)**: Gerencia a interação com o usuário, exibindo alertas, progresso e recebendo comandos.