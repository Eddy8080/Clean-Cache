# 🛡️ Clean Cache - Security & Cleaner

**Clean Cache** é uma ferramenta robusta desenvolvida em Python para Windows que combina otimização de sistema com segurança cibernética avançada. O software monitora diretórios em tempo real, realiza limpeza de arquivos temporários e utiliza múltiplas camadas de análise (Assinaturas, IA e Nuvem) para detectar ameaças.

---

## 🚀 Funcionalidades Principais

### 🔒 Segurança em Camadas (Defense in Depth)
*   **Monitoramento em Tempo Real**: Utiliza `watchdog` para detectar novos arquivos instantaneamente.
*   **Análise de Assinaturas (YARA)**: Detecção local baseada em regras para malwares e ransomwares conhecidos.
*   **Inteligência Artificial (Heurística)**: Modelo de Machine Learning (`scikit-learn/RandomForest`) treinado para identificar anomalias na estrutura de arquivos executáveis (PE).
*   **Verificação em Nuvem**: Integração com a API do **VirusTotal** para checar a reputação de arquivos suspeitos.
*   **Validação de Confiança**: Verifica assinaturas digitais nativas do Windows (`WinVerifyTrust`) para evitar falsos positivos em softwares legítimos.

### 🧹 Otimização e Utilitários
*   **Limpeza Automática**: Remove arquivos da pasta `%TEMP%` do Windows para liberar espaço.
*   **Análise de Compactados**: Capacidade de inspecionar o conteúdo de arquivos `.zip` e imagens `.iso` sem necessidade de extração completa prévia.
*   **Verificação de Processos**: Impede erros de exclusão verificando se o arquivo está em uso por outro processo (`psutil`).

### 💻 Interface Gráfica (GUI)
*   **Dashboard Interativo**: Desenvolvido com `FreeSimpleGUI`.
*   **Visualização de Dados**: Gráficos estatísticos em tempo real gerados com `Matplotlib`.
*   **Feedback Visual**: Barra de progresso com estimativa de tempo (ETA) e logs detalhados.

---

## 🛠️ Tecnologias Utilizadas

*   **Linguagem**: Python 3.10+
*   **Interface**: FreeSimpleGUI
*   **Análise de Dados/Gráficos**: Matplotlib, Scikit-learn, Numpy
*   **Segurança/Sistema**: YARA-Python, Pefile, Psutil, Requests, Pycdlib, Watchdog

---

## ⚙️ Instalação e Configuração

### Pré-requisitos
*   Python instalado.
*   Microsoft C++ Build Tools (necessário para compilar o `yara-python` no Windows).

### Passo a Passo

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/Eddy8080/Clean-Cache.git
   cd Clean-Cache
   ```

2. **Crie um ambiente virtual (Recomendado):**
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuração da API (Opcional):**
   Para habilitar a verificação no VirusTotal, configure a variável de ambiente ou edite o arquivo `brain.py`:
   ```python
   self.vt_api_key = os.getenv('VT_API_KEY', 'SUA_CHAVE_AQUI')
   ```

---

## ▶️ Como Usar

1. Execute o arquivo principal:
   ```bash
   python main.py
   ```
2. Na interface:
   *   **Alvo**: Selecione a pasta ou unidade que deseja monitorar.
   *   **Iniciar Monitoramento**: Começa a varredura e a vigilância em tempo real.
   *   **Acompanhamento**: Observe o gráfico de ameaças e o log de atividades.
   *   **Ação**: Caso ameaças sejam detectadas, clique no botão **Escudo (🛡️)** para aplicar as correções (remoção dos arquivos maliciosos).
   *   **Relatório**: Clique no botão **Salvar (💾)** para exportar o log da sessão.