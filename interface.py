import FreeSimpleGUI as sg
import matplotlib
matplotlib.use('TkAgg') # Backend para integração com PySimpleGUI/Tkinter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
import os

class CleanCacheUI:
    def __init__(self):
        sg.theme('DarkBlue3')
        self.window = None
        self.fig = None
        self.canvas_agg = None

    def _draw_figure(self, canvas, figure):
        """Método auxiliar para desenhar o gráfico do Matplotlib no Canvas do PySimpleGUI"""
        figure_canvas_agg = FigureCanvasTkAgg(figure, canvas)
        figure_canvas_agg.draw()
        figure_canvas_agg.get_tk_widget().pack(side='top', fill='both', expand=1)
        return figure_canvas_agg

    def exibir_boas_vindas(self):
        # Layout otimizado para telas de 14" (Colunas lado a lado)
        col_esquerda = [
            [sg.Frame('Status da Varredura', [
                [sg.Text('Aguardando início...', key='-STATUS-', size=(30, 1), expand_x=True)],
                [sg.Text('', key='-CURRENT-FILE-', size=(30, 1), text_color='#00FF00', font=('Consolas', 8), expand_x=True)],
                [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROG-', expand_x=True)]
            ], expand_x=True)],
            [sg.Frame('Monitoramento de Ameaças', [[sg.Canvas(key='-CANVAS-', size=(350, 250))]])]
        ]

        col_direita = [
            [sg.Frame('Log de Atividades', [
                [sg.Multiline(size=(40, 20), key='-LOG-', autoscroll=True, disabled=True, expand_x=True, expand_y=True),
                 sg.Column([
                     [sg.Button('🛡️', key='-APPLY-', size=(3, 1), tooltip='Aplicar Solução (Remover Ameaças)')],
                     [sg.Button('💾', key='-EXPORT-', size=(3, 1), tooltip='Exportar Relatório')]
                 ], vertical_alignment='bottom')]
            ], expand_x=True, expand_y=True)]
        ]

        layout = [
            [sg.Text('Clean Cache - Security & Cleaner', font=('Helvetica', 16, 'bold'))],
            [sg.Frame('Controle do Sistema', [
                [sg.Text('Alvo:', size=(5, 1)), sg.Input(default_text='.', key='-PATH-', size=(30, 1), expand_x=True), sg.FolderBrowse('Selecionar', initial_folder=os.getcwd())],
                [sg.Button('Iniciar Monitoramento', key='-START-', size=(20, 1)), sg.Button('Parar', key='-STOP-', size=(10, 1), disabled=True)]
            ], expand_x=True)],
            [sg.Column(col_esquerda, vertical_alignment='top', expand_y=True), 
             sg.Column(col_direita, vertical_alignment='top', expand_x=True, expand_y=True)],
            [sg.Button('Sair', size=(10, 1))]
        ]

        self.window = sg.Window('Clean Cache', layout, finalize=True, resizable=True, size=(900, 600))
        
        # Gera o gráfico inicial
        self.atualizar_grafico_ameacas()
        self.exibir_mensagem("Sistema inicializado e pronto.")

    def atualizar_grafico_ameacas(self, ameacas=None, total_arquivos=0, total_infectados=0):
        """Gera um gráfico de barras mostrando estatísticas da varredura"""
        if self.canvas_agg:
            self.canvas_agg.get_tk_widget().forget()
            plt.close('all')

        # Dados para o gráfico de barras
        labels = ['Total', 'Limpos', 'Infectados']
        limpos = max(0, total_arquivos - total_infectados)
        values = [total_arquivos, limpos, total_infectados]
        colors = ['#2196F3', '#4CAF50', '#F44336'] # Azul, Verde, Vermelho

        fig = plt.figure(figsize=(3.5, 2.5), dpi=100)
        ax = fig.add_subplot(111)
        
        bars = ax.bar(labels, values, color=colors)
        
        # Adiciona o valor exato acima de cada barra
        ax.bar_label(bars, padding=3, fontsize=8)
            
        ax.set_title("Estatísticas da Varredura", fontsize=10)
        ax.tick_params(axis='both', labelsize=8)
        fig.tight_layout()

        self.canvas_agg = self._draw_figure(self.window['-CANVAS-'].TKCanvas, fig)

    def atualizar_progresso(self, valor, mensagem=None):
        """Atualiza a barra de progresso e o texto de status"""
        if self.window:
            self.window['-PROG-'].update(valor)
            if mensagem:
                self.window['-STATUS-'].update(mensagem)

    def confirmar_remocao(self, arquivo, ameaca):
        """Solicita confirmação do usuário para remover um arquivo infectado"""
        if not self.window:
            return False
            
        resposta = sg.popup_yes_no(
            f"ALERTA DE SEGURANÇA!\n\n"
            f"Ameaça detectada: {ameaca}\n"
            f"Arquivo: {arquivo}\n\n"
            f"Deseja remover este arquivo imediatamente?",
            title="Confirmação de Remoção",
            icon=sg.SYSTEM_TRAY_ICON,
            keep_on_top=True
        )
        return resposta == 'Yes'

    def confirmar_solucao_em_massa(self, lista_arquivos):
        """Mostra lista de arquivos a serem removidos e pede confirmação"""
        if not self.window or not lista_arquivos:
            sg.popup("Nenhuma ameaça pendente para solução.", title="Sistema Seguro")
            return False
            
        texto_arquivos = "\n".join(lista_arquivos)
        layout = [
            [sg.Text("As seguintes ameaças foram identificadas e serão removidas:", text_color='red')],
            [sg.Multiline(texto_arquivos, size=(60, 10), disabled=True)],
            [sg.Text("Deseja aplicar a solução e excluir estes arquivos permanentemente?", font=('bold'))],
            [sg.Button('Sim, Aplicar Solução', key='-CONFIRM-YES-'), sg.Button('Cancelar')]
        ]
        window_popup = sg.Window("Aplicar Solução", layout, modal=True)
        event, _ = window_popup.read()
        window_popup.close()
        return event == '-CONFIRM-YES-'

    def salvar_relatorio(self):
        """Salva o conteúdo do log em um arquivo de texto"""
        if not self.window:
            return
        
        conteudo = self.window['-LOG-'].get()
        filename = sg.popup_get_file('Salvar Relatório', save_as=True, default_extension='.txt', file_types=(("Text Files", "*.txt"),))
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(conteudo)
            sg.popup_quick_message(f'Relatório salvo em:\n{filename}', background_color='green', text_color='white')

    def atualizar_botoes(self, em_execucao):
        """Atualiza o estado dos botões de controle"""
        if self.window:
            self.window['-START-'].update(disabled=em_execucao)
            self.window['-STOP-'].update(disabled=not em_execucao)

    def notificar_ameaca(self, ameacas, total_arquivos=0, total_infectados=0):
        """Envia um evento thread-safe para atualizar o gráfico de ameaças"""
        if self.window:
            self.window.write_event_value('-UPDATE-GRAPH-', (ameacas, total_arquivos, total_infectados))

    def atualizar_status_arquivo(self, mensagem):
        """Envia evento para atualizar apenas o texto do arquivo atual (rápido)"""
        if self.window:
            self.window.write_event_value('-SCAN-UPDATE-', mensagem)

    def atualizar_progresso_safe(self, valor, mensagem=None):
        """Envia evento thread-safe para atualizar progresso"""
        if self.window:
            self.window.write_event_value('-UPDATE-PROG-', (valor, mensagem))

    def processar_eventos(self):
        """Gerencia o loop de eventos da interface"""
        if not self.window:
            return False, None, None
            
        event, values = self.window.read(timeout=100)
        
        if event == sg.WIN_CLOSED or event == 'Sair':
            return False, event, None
            
        # Processa mensagens enviadas de outras threads (thread-safe)
        if event == '-LOG-MSG-':
            self.window['-LOG-'].print(f"[INFO] {values[event]}")
        elif event == '-LOG-ALERT-':
            self.window['-LOG-'].print(f"[ALERTA] {values[event]}", text_color='red', font=('Helvetica', 10, 'bold'))
        elif event == '-UPDATE-GRAPH-':
            ameacas, total, infectados = values[event]
            self.atualizar_grafico_ameacas(ameacas, total, infectados)
        elif event == '-SCAN-UPDATE-':
            self.window['-CURRENT-FILE-'].update(values[event])
        elif event == '-UPDATE-PROG-':
            valor, msg = values[event]
            self.atualizar_progresso(valor, msg)
            
        return True, event, values

    def fechar(self):
        if self.window:
            self.window.close()

    def exibir_mensagem(self, mensagem):
        if self.window:
            self.window.write_event_value('-LOG-MSG-', mensagem)
        else:
            print(f"[INFO] {mensagem}")

    def exibir_alerta(self, mensagem):
        if self.window:
            self.window.write_event_value('-LOG-ALERT-', mensagem)
        else:
            print(f"[ALERTA] {mensagem}")