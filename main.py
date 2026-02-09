import sys
import time
from brain import CleanCacheBrain
from interface import CleanCacheUI

def main():
    # 1. Inicializa a Interface (UX)
    ui = CleanCacheUI()
    ui.exibir_boas_vindas()

    # 2. Inicializa o Cérebro (Lógica)
    # Passamos os callbacks da UI para o cérebro
    brain = CleanCacheBrain(
        log_callback=ui.exibir_mensagem,
        alert_callback=ui.exibir_alerta,
        threat_callback=ui.notificar_ameaca,
        status_callback=ui.atualizar_status_arquivo,
        progress_callback=ui.atualizar_progresso_safe
    )

    try:
        ui.exibir_mensagem("Motor pronto. Aguardando comando...")
        
        # Loop principal da GUI
        while True:
            # Processa eventos da interface gráfica e verifica se deve fechar
            continuar, evento, values = ui.processar_eventos()
            if not continuar:
                break
            
            if evento == '-START-':
                path = values.get('-PATH-', '.')
                if not path: path = "."
                ui.exibir_mensagem(f"Iniciando monitoramento em: {path}")
                brain.iniciar_monitoramento(path_to_watch=path)
                ui.atualizar_botoes(em_execucao=True)
            elif evento == '-STOP-':
                ui.exibir_mensagem("Parando monitoramento...")
                brain.parar_sistema()
                ui.atualizar_botoes(em_execucao=False)
            elif evento == '-EXPORT-':
                ui.salvar_relatorio()
            elif evento == '-APPLY-':
                # Obtém lista de infectados do cérebro
                ameacas = brain.arquivos_infectados
                if ui.confirmar_solucao_em_massa(ameacas):
                    ui.exibir_mensagem("Aplicando as correções...")
                    qtd, erros = brain.executar_limpeza()
                    ui.exibir_mensagem(f"Correções bem sucedidas. {qtd} ameaças neutralizadas.")
            
    except KeyboardInterrupt:
        pass
    finally:
        ui.exibir_mensagem("Parando o sistema...")
        brain.parar_sistema()
        ui.fechar()
        sys.exit(0)

if __name__ == "__main__":
    main()