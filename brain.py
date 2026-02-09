import os
import sys
import time
import threading
import hashlib
import json
import zipfile
import pycdlib
import ctypes

# Bibliotecas de Segurança e Sistema
import yara
import pefile
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Bibliotecas de IA
from sklearn.ensemble import RandomForestClassifier
import numpy as np

class SecurityHandler(FileSystemEventHandler):
    """Manipulador de eventos do sistema de arquivos para o Watchdog"""
    def __init__(self, brain_instance):
        self.brain = brain_instance

    def on_created(self, event):
        if not event.is_directory:
            self.brain.analisar_arquivo(event.src_path)

class CleanCacheBrain:
    def __init__(self, log_callback=None, alert_callback=None, threat_callback=None, status_callback=None, progress_callback=None):
        self.log_callback = log_callback
        self.alert_callback = alert_callback
        self.threat_callback = threat_callback
        self.status_callback = status_callback
        self.progress_callback = progress_callback
        self.observer = None
        self.running = False
        self.ameacas_detectadas = {}
        self.arquivos_infectados = [] # Lista para armazenar caminhos completos das ameaças
        self.total_analisados = 0
        self.last_ui_update = 0
        self.last_progress_update = 0
        self.ui_update_interval = 0.1 # Intervalo de atualização da UI (segundos) para performance
        
        # Configuração YARA (Regras básicas para Ransomware e Testes)
        # Em produção, carregaríamos de um arquivo .yar externo
        self.regras_yara = yara.compile(source="""
            rule Ransomware_Suspeito {
                strings:
                    $s1 = "wannacry" nocase
                    $s2 = "encrypted" nocase
                    $s3 = "bitcoin" nocase
                condition:
                    any of them
            }
        """)
        
        # Inicialização do Modelo de IA (Scikit-Learn)
        # Treinamento simulado (Features: [Tamanho_KB, Num_Seções])
        # 0 = Seguro, 1 = Suspeito
        self.modelo_ia = RandomForestClassifier(n_estimators=10, random_state=42)
        X_treino = np.array([
            [100, 5], [500, 6], [2000, 4],  # Padrões normais
            [10, 0], [50, 1], [15, 99]      # Padrões anômalos (muito pequeno/sem seções ou muitas seções)
        ])
        y_treino = np.array([0, 0, 0, 1, 1, 1])
        self.modelo_ia.fit(X_treino, y_treino)
        
        # Chave de API do VirusTotal (Placeholder - Substituir por chave real ou variável de ambiente)
        self.vt_api_key = os.getenv('VT_API_KEY', '') 

    def _atualizar_status(self, mensagem):
        if self.status_callback:
            self.status_callback(mensagem)
            
    def _atualizar_progresso(self, valor, mensagem=None):
        if self.progress_callback:
            self.progress_callback(valor, mensagem)

    def _notificar(self, mensagem, tipo='INFO'):
        if tipo == 'ALERTA' and self.alert_callback:
            self.alert_callback(mensagem)
        elif self.log_callback:
            self.log_callback(mensagem)
        else:
            print(f"[{tipo}] {mensagem}")

    def _registrar_ameaca(self, tipo_ameaca, caminho_arquivo=None):
        self.ameacas_detectadas[tipo_ameaca] = self.ameacas_detectadas.get(tipo_ameaca, 0) + 1
        
        if caminho_arquivo and caminho_arquivo not in self.arquivos_infectados:
            self.arquivos_infectados.append(caminho_arquivo)
            
        if self.threat_callback:
            self.threat_callback(self.ameacas_detectadas, self.total_analisados, len(self.arquivos_infectados))

    def calcular_hash(self, caminho):
        """Gera o hash SHA256 do arquivo"""
        sha256_hash = hashlib.sha256()
        try:
            with open(caminho, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def verificar_virustotal(self, file_hash):
        """Consulta a API do VirusTotal (Simulação de IA Externa)"""
        if not self.vt_api_key:
            return None
            
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                dados = response.json()
                stats = dados.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                return malicious
            elif response.status_code == 404:
                return 0 # Arquivo desconhecido (provavelmente limpo ou novo)
        except Exception as e:
            self._notificar(f"Erro na conexão com VirusTotal: {e}", 'INFO')
        return None

    def extrair_features_ia(self, caminho):
        """Extrai características numéricas para o modelo de Machine Learning"""
        try:
            tamanho_kb = os.path.getsize(caminho) / 1024
            num_secoes = 0
            if caminho.lower().endswith(('.exe', '.dll')):
                try:
                    pe = pefile.PE(caminho)
                    num_secoes = len(pe.sections)
                    pe.close()
                except:
                    pass
            return [tamanho_kb, num_secoes]
        except:
            return None

    def verificar_assinatura_digital(self, caminho):
        """Verifica se o arquivo possui uma assinatura digital válida (Trusted/Homologado)"""
        try:
            # Constantes para WinVerifyTrust
            WTD_UI_NONE = 2
            WTD_REVOKE_NONE = 0
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 1
            WTD_STATEACTION_CLOSE = 2
            
            # Estruturas ctypes necessárias
            class GUID(ctypes.Structure):
                _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
            
            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [("cbStruct", ctypes.c_ulong), ("pcwszFilePath", ctypes.c_wchar_p), ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.POINTER(GUID))]
            
            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [("cbStruct", ctypes.c_ulong), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", ctypes.c_ulong), ("fdwRevocationChecks", ctypes.c_ulong), ("dwUnionChoice", ctypes.c_ulong), ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", ctypes.c_ulong), ("hWVTStateData", ctypes.c_void_p), ("pwszURLReference", ctypes.c_wchar_p), ("dwProvFlags", ctypes.c_ulong), ("dwUIContext", ctypes.c_ulong), ("pSignatureSettings", ctypes.c_void_p)]

            guid = GUID(0x00AAC56B, 0xCD44, 0x11d0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
            file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), os.path.abspath(caminho), None, None)
            trust_data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, ctypes.pointer(file_info), WTD_STATEACTION_VERIFY, None, None, 0, 0, None)
            
            wintrust = ctypes.windll.wintrust
            result = wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(trust_data))
            
            # Limpa estado
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(trust_data))
            
            return result == 0
        except:
            return False

    def analisar_arquivo(self, caminho, dentro_de_zip=False):
        """Analisa um arquivo e atualiza a interface"""
        # Ignora arquivos temporários do sistema ou do próprio python
        if not os.path.exists(caminho) or caminho.endswith('.tmp'):
            return

        nome_arquivo = os.path.basename(caminho)
        
        # 0. Verificação de Assinatura Digital (Homologação)
        # Se o arquivo for um executável assinado e confiável, pulamos a análise pesada
        if not dentro_de_zip and nome_arquivo.lower().endswith(('.exe', '.dll', '.sys', '.msi')):
            if self.verificar_assinatura_digital(caminho):
                self._atualizar_status(f"✅ Arquivo Homologado (Assinado): {nome_arquivo}")
                return
        
        # Tratamento especial para arquivos compactados (ZIP)
        # ISOs requerem bibliotecas externas (pycdlib), aqui tratamos ZIP nativamente
        if caminho.lower().endswith('.zip'):
            try:
                if zipfile.is_zipfile(caminho):
                    with zipfile.ZipFile(caminho, 'r') as z:
                        lista_arquivos = z.namelist()
                        total = len(lista_arquivos)
                        self._atualizar_status(f"📦 Verificando ZIP: {nome_arquivo} ({total} itens)")
                        
                        start_time_zip = time.time()
                        for i, item in enumerate(lista_arquivos):
                            self.total_analisados += 1
                            # Simula o tempo de extração/análise
                            if not self.running: break
                            
                            current_time = time.time()
                            if current_time - self.last_ui_update > self.ui_update_interval:
                                # Estimativa de tempo em tempo real
                                processados = i + 1
                                tempo_decorrido = current_time - start_time_zip
                                tempo_medio = tempo_decorrido / processados if processados > 0 else 0.1
                                tempo_restante = tempo_medio * (total - processados)
                                
                                msg_progresso = f"   ↳ [{i+1}/{total}] Verificando: {item} (ETA: {tempo_restante:.1f}s)"
                                self._atualizar_status(msg_progresso)
                                self.last_ui_update = current_time
                            
                            # Aqui poderíamos extrair para temp e analisar recursivamente
                            # Por segurança e performance, apenas listamos e verificamos nomes suspeitos por enquanto
                            if item.lower().endswith(('.exe', '.bat', '.vbs')):
                                self._notificar(f"   ⚠️ Executável dentro do zip: {item}", 'ALERTA')
                                # Marcamos o container ZIP como infectado
                                self._registrar_ameaca('Executável em Compactado', caminho)
                        return # Finaliza análise do container zip
            except Exception as e:
                self._notificar(f"Erro ao ler compactado {nome_arquivo}: {e}", 'INFO')

        # Tratamento para imagens de disco (ISO)
        elif caminho.lower().endswith('.iso'):
            try:
                iso = pycdlib.PyCdlib()
                iso.open(caminho)
                arquivos_iso = []
                # Caminha pela estrutura da ISO para listar arquivos
                for dirname, dirlist, filelist in iso.walk(iso_path='/'):
                    for filename in filelist:
                        arquivos_iso.append(filename)
                
                total = len(arquivos_iso)
                self._atualizar_status(f"💿 Verificando ISO: {nome_arquivo} ({total} itens)")
                
                start_time_iso = time.time()
                for i, item in enumerate(arquivos_iso):
                    self.total_analisados += 1
                    if not self.running: break
                    
                    current_time = time.time()
                    if current_time - self.last_ui_update > self.ui_update_interval:
                        # Estimativa de tempo em tempo real
                        processados = i + 1
                        tempo_decorrido = current_time - start_time_iso
                        tempo_medio = tempo_decorrido / processados if processados > 0 else 0.1
                        tempo_restante = tempo_medio * (total - processados)
                        
                        msg_progresso = f"   ↳ [{i+1}/{total}] Verificando: {item} (ETA: {tempo_restante:.1f}s)"
                        self._atualizar_status(msg_progresso)
                        self.last_ui_update = current_time
                    
                    if str(item).lower().endswith(('.exe', '.bat', '.vbs')):
                        self._notificar(f"   ⚠️ Executável dentro da ISO: {item}", 'ALERTA')
                        self._registrar_ameaca('Executável em ISO', caminho)
                iso.close()
                return
            except Exception as e:
                self._notificar(f"Erro ao ler ISO {nome_arquivo}: {e}", 'INFO')

        if not dentro_de_zip:
            self.total_analisados += 1
            current_time = time.time()
            # Força atualização para arquivos importantes ou se passou o intervalo de tempo
            if nome_arquivo.lower().endswith(('.exe', '.zip', '.iso', '.msi')) or (current_time - self.last_ui_update > self.ui_update_interval):
                self._atualizar_status(f"Analisando: {nome_arquivo}")
                self.last_ui_update = current_time
        
        # 1. Análise YARA (Local e Rápida)
        try:
            matches = self.regras_yara.match(caminho)
            if matches:
                self._notificar(f"YARA detectou padrão suspeito: {matches[0]} em {nome_arquivo}", 'ALERTA')
                self._registrar_ameaca('Ransomware/Malware (YARA)', caminho)
                return # Se já detectou localmente, não gasta cota de API
        except Exception as e:
            pass

        # 2. Análise Heurística (Scikit-Learn)
        features = self.extrair_features_ia(caminho)
        if features:
            predicao = self.modelo_ia.predict([features])[0]
            if predicao == 1:
                self._notificar(f"IA detectou anomalia heurística em: {nome_arquivo}", 'ALERTA')
                self._registrar_ameaca('Anomalia (Machine Learning)', caminho)

        # 3. Análise VirusTotal (Nuvem - Apenas para executáveis para economizar API)
        if nome_arquivo.lower().endswith(('.exe', '.dll', '.msi')):
            file_hash = self.calcular_hash(caminho)
            malicious_count = self.verificar_virustotal(file_hash)
            if malicious_count and malicious_count > 0:
                self._notificar(f"VirusTotal detectou {malicious_count} alertas para {nome_arquivo}", 'ALERTA')
                self._registrar_ameaca('Ameaça Confirmada (VirusTotal)', caminho)

    def _scan_inicial(self, abs_path):
        """Executa a varredura inicial em uma thread separada"""
        if os.path.isdir(abs_path):
            try:
                # Pré-listagem para calcular total de arquivos e permitir barra de progresso
                arquivos_para_analisar = []
                for item in os.listdir(abs_path):
                    caminho_completo = os.path.join(abs_path, item)
                    if os.path.isfile(caminho_completo):
                        arquivos_para_analisar.append(caminho_completo)
                
                total = len(arquivos_para_analisar)
                start_time = time.time()

                if total == 0:
                    self._atualizar_progresso(100, "Nenhum arquivo encontrado.")
                    return

                for i, caminho_completo in enumerate(arquivos_para_analisar):
                    if not self.running: break
                    
                    self.analisar_arquivo(caminho_completo)
                    
                    current_time = time.time()
                    # Atualiza progresso apenas em intervalos para performance (ou no final)
                    if current_time - self.last_progress_update > self.ui_update_interval or i + 1 == total:
                        # Cálculos de Progresso e ETA
                        processados = i + 1
                        porcentagem = (processados / total) * 100
                        tempo_decorrido = current_time - start_time
                        
                        if processados > 0:
                            tempo_medio = tempo_decorrido / processados
                            tempo_restante = tempo_medio * (total - processados)
                            eta_str = f"{tempo_restante:.0f}s" if tempo_restante < 60 else f"{tempo_restante/60:.1f}min"
                            self._atualizar_progresso(porcentagem, f"Varredura em andamento... {porcentagem:.1f}% (ETA: {eta_str})")
                        self.last_progress_update = current_time
                
                self._atualizar_progresso(100, "Varredura concluída.")
            except Exception as e:
                self._notificar(f"Erro ao listar conteúdo da pasta: {e}", 'ALERTA')

    def limpar_temp(self):
        """Tenta limpar a pasta %TEMP% do Windows"""
        temp_path = os.environ.get('TEMP')
        if not temp_path or not os.path.exists(temp_path):
            return

        self._notificar(f"Iniciando limpeza automática de TEMP...", 'INFO')
        removidos = 0
        bytes_liberados = 0
        
        # Percorre de baixo para cima para remover arquivos antes das pastas
        for root, dirs, files in os.walk(temp_path, topdown=False):
            for name in files:
                caminho_arquivo = os.path.join(root, name)
                try:
                    tamanho = os.path.getsize(caminho_arquivo)
                    os.remove(caminho_arquivo)
                    removidos += 1
                    bytes_liberados += tamanho
                except:
                    pass # Arquivo em uso, ignora
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                    removidos += 1
                except:
                    pass
        
        # Formata o tamanho liberado
        if bytes_liberados < 1024:
            tamanho_str = f"{bytes_liberados} B"
        elif bytes_liberados < 1024 * 1024:
            tamanho_str = f"{bytes_liberados / 1024:.2f} KB"
        else:
            tamanho_str = f"{bytes_liberados / (1024 * 1024):.2f} MB"
            
        self._notificar(f"Limpeza de TEMP finalizada: {removidos} itens removidos. Espaço liberado: {tamanho_str}", 'INFO')

    def iniciar_monitoramento(self, path_to_watch="."):
        """Inicia o monitoramento de diretório em tempo real"""
        abs_path = os.path.abspath(path_to_watch)
        self._notificar(f"Iniciando monitoramento em: {abs_path}", 'INFO')
        self.running = True
        
        # Inicia limpeza do TEMP em background
        threading.Thread(target=self.limpar_temp, daemon=True).start()
        
        # Inicia scan inicial em Thread separada para não travar a GUI
        threading.Thread(target=self._scan_inicial, args=(abs_path,), daemon=True).start()
        
        event_handler = SecurityHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, path_to_watch, recursive=False)
        self.observer.start()

    def parar_sistema(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.running = False

    def verificar_arquivo_em_uso(self, caminho):
        """Verifica se o arquivo está sendo usado por algum processo (usando psutil)"""
        try:
            caminho_abs = os.path.abspath(caminho)
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for file in proc.info['open_files']:
                            if os.path.abspath(file.path) == caminho_abs:
                                return True, proc.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        return False, None

    def executar_limpeza(self):
        """Aplica a solução removendo os arquivos listados como infectados"""
        removidos = []
        erros = []
        
        for arquivo in self.arquivos_infectados:
            # Verifica se está em uso antes de tentar deletar
            em_uso, nome_processo = self.verificar_arquivo_em_uso(arquivo)
            if em_uso:
                msg = f"Arquivo {os.path.basename(arquivo)} está em uso pelo processo '{nome_processo}'. Não foi possível remover."
                erros.append(msg)
                self._notificar(msg, 'ALERTA')
                continue

            try:
                if os.path.exists(arquivo):
                    os.remove(arquivo) # Usa biblioteca OS nativa para remoção
                    removidos.append(arquivo)
                    self._notificar(f"Solução aplicada: {os.path.basename(arquivo)} removido com sucesso.", 'INFO')
            except Exception as e:
                erros.append(f"{os.path.basename(arquivo)}: {e}")
                self._notificar(f"Falha ao remover {os.path.basename(arquivo)}: {e}", 'ALERTA')
        
        # Limpa a lista de infectados dos que foram removidos com sucesso
        self.arquivos_infectados = [arq for arq in self.arquivos_infectados if arq not in removidos]
        return len(removidos), erros