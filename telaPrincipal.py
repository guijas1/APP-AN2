import flet as ft
import subprocess
import threading
import os
import sys
from datetime import datetime

# ------------------------------
# Utilidades
# ------------------------------

def is_windows() -> bool:
    return sys.platform.startswith("win")


def run_cmd(cmd: str, use_powershell: bool = False) -> tuple[int, str]:
    """Executa um comando no Windows e retorna (returncode, saída+erros).
    Se use_powershell=True, força execução via PowerShell.
    """
    if not is_windows():
        return 1, "Este app foi feito para Windows."

    try:
        if use_powershell:
            full_cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                cmd,
            ]
            proc = subprocess.run(full_cmd, capture_output=True, text=True)
        else:
            # Usando cmd.exe
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=True)

        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except Exception as e:
        return 1, f"Erro ao executar comando: {e}"


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------
# App Flet
# ------------------------------

def main(page: ft.Page):
    page.title = "Suporte N2 - Windows Toolkit (Protótipo)"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.window_min_height = 700
    page.window_min_width = 1000

    # ------------- Área de LOG -------------
    log_output = ft.TextField(
        value="",
        multiline=True,
        read_only=True,
        expand=True,
        text_style=ft.TextStyle(font_family="Consolas", size=13),
        hint_text="Saída dos comandos aparecerá aqui...",
    )

    def append_log(text: str):
        log_output.value += f"[{timestamp()}] {text}\n"
        page.update()

    def append_block(title: str, body: str):
        sep = "-" * 60
        log_output.value += f"\n{sep}\n# {title}\n{sep}\n{body}\n"
        page.update()

    # ------------- Execução assíncrona simples (thread) -------------
    def run_in_thread(fn, *args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True).start()

    # ------------- Campos de entrada -------------
    host_field = ft.TextField(label="Host/IP", hint_text="ex.: 8.8.8.8 ou dominio.com", width=260)
    port_field = ft.TextField(label="Porta (opcional)", hint_text="ex.: 443", width=160)

    # ------------- Handlers de Rede -------------
    def do_ipconfig_all(e=None):
        def task():
            append_log("Executando: ipconfig /all")
            rc, out = run_cmd("ipconfig /all")
            append_block("ipconfig /all", out)
        run_in_thread(task)

    def do_ping(e=None):
        host = host_field.value.strip()
        if not host:
            append_log("Informe um host antes de pingar.")
            return
        def task():
            append_log(f"Pingando {host} (4 pacotes)...")
            rc, out = run_cmd(f"ping -n 4 {host}")
            append_block(f"ping {host}", out)
        run_in_thread(task)

    def do_tracert(e=None):
        host = host_field.value.strip()
        if not host:
            append_log("Informe um host antes de executar o tracert.")
            return
        def task():
            append_log(f"Executando tracert para {host}...")
            rc, out = run_cmd(f"tracert {host}")
            append_block(f"tracert {host}", out)
        run_in_thread(task)

    def do_nslookup(e=None):
        host = host_field.value.strip()
        if not host:
            append_log("Informe um host/domínio antes de executar o nslookup.")
            return
        def task():
            append_log(f"Executando nslookup em {host}...")
            rc, out = run_cmd(f"nslookup {host}")
            append_block(f"nslookup {host}", out)
        run_in_thread(task)

    def do_test_port(e=None):
        host = host_field.value.strip()
        port = port_field.value.strip()
        if not host or not port:
            append_log("Informe host e porta para testar conectividade TCP.")
            return
        def task():
            append_log(f"Testando porta TCP {host}:{port} (PowerShell Test-NetConnection)...")
            ps = f"Test-NetConnection -ComputerName '{host}' -Port {port} | Out-String"
            rc, out = run_cmd(ps, use_powershell=True)
            append_block(f"Test-NetConnection {host}:{port}", out)
        run_in_thread(task)

    def do_release(e=None):
        def task():
            append_log("Liberando IP (ipconfig /release)...")
            rc, out = run_cmd("ipconfig /release")
            append_block("ipconfig /release", out)
        run_in_thread(task)

    def do_renew(e=None):
        def task():
            append_log("Renovando IP (ipconfig /renew)...")
            rc, out = run_cmd("ipconfig /renew")
            append_block("ipconfig /renew", out)
        run_in_thread(task)

    def do_reset_tcpip(e=None):
        def task():
            append_log("Resetando stack TCP/IP (netsh int ip reset) — pode exigir reinício e privilégios de administrador.")
            rc, out = run_cmd("netsh int ip reset")
            append_block("netsh int ip reset", out)
        run_in_thread(task)

    def do_reset_winsock(e=None):
        def task():
            append_log("Resetando Winsock (netsh winsock reset) — pode exigir reinício e privilégios de administrador.")
            rc, out = run_cmd("netsh winsock reset")
            append_block("netsh winsock reset", out)
        run_in_thread(task)

    # ------------- Handlers de Sistema -------------
    def do_systeminfo(e=None):
        def task():
            append_log("Coletando informações do sistema (systeminfo)...")
            rc, out = run_cmd("systeminfo")
            append_block("systeminfo", out)
        run_in_thread(task)

    def do_uptime(e=None):
        def task():
            append_log("Obtendo uptime (PowerShell Get-Uptime)...")
            ps = "(Get-Uptime) | Out-String"
            rc, out = run_cmd(ps, use_powershell=True)
            append_block("Get-Uptime", out)
        run_in_thread(task)

    # ------------- Ferramentas rápidas (abrir apps nativos) -------------
    def open_tool(cmd: str, title: str):
        def task():
            append_log(f"Abrindo {title}...")
            try:
                # Abrir como novo processo sem capturar saída
                subprocess.Popen(cmd, shell=True)
                append_log(f"{title} solicitado.")
            except Exception as e:
                append_log(f"Falha ao abrir {title}: {e}")
        run_in_thread(task)

    # ------------- Exportar LOG -------------
    file_picker = ft.FilePicker()
    page.overlay.append(file_picker)

    def save_log(e=None):
        def on_result(e: ft.FilePickerResultEvent):
            if e.path:
                try:
                    with open(e.path, "w", encoding="utf-8") as f:
                        f.write(log_output.value)
                    append_log(f"Log salvo em: {e.path}")
                except Exception as ex:
                    append_log(f"Erro ao salvar: {ex}")
        file_picker.on_result = on_result
        file_picker.save_file(file_name="suporte_n2_log.txt")

    # ------------- UI: Grupos e Botões -------------
    rede_controls = [
        ft.Row([host_field, port_field], alignment=ft.MainAxisAlignment.START),
        ft.Row([
            ft.ElevatedButton("IPCONFIG /ALL", icon=ft.Icons.ROUTER, on_click=do_ipconfig_all),
            ft.ElevatedButton("PING", icon=ft.Icons.PLAY_ARROW, on_click=do_ping),
            ft.ElevatedButton("TRACERT", icon=ft.Icons.SHARE_ARRIVAL_TIME, on_click=do_tracert),
            ft.ElevatedButton("NSLOOKUP", icon=ft.Icons.SEARCH, on_click=do_nslookup),
            ft.ElevatedButton("TESTAR PORTA", icon=ft.Icons.CHECK_CIRCLE, on_click=do_test_port),
        ], wrap=True, spacing=10),
        ft.Row([
            ft.OutlinedButton("RELEASE IP", icon=ft.Icons.SETTINGS_BACKUP_RESTORE, on_click=do_release),
            ft.OutlinedButton("RENEW IP", icon=ft.Icons.CACHED, on_click=do_renew),
            ft.OutlinedButton("RESET TCP/IP", icon=ft.Icons.RESTART_ALT, on_click=do_reset_tcpip),
            ft.OutlinedButton("RESET WINSOCK", icon=ft.Icons.SETTINGS_ETHERNET, on_click=do_reset_winsock),
        ], wrap=True, spacing=10),
    ]

    sistema_controls = [
        ft.Row([
            ft.ElevatedButton("SYSTEMINFO", icon=ft.Icons.DESKTOP_WINDOWS, on_click=do_systeminfo),
            ft.ElevatedButton("UPTIME", icon=ft.Icons.ACCESS_TIME, on_click=do_uptime),
        ], wrap=True, spacing=10),
    ]

    ferramentas_controls = [
        ft.Row([
            ft.FilledButton("Ger. de Tarefas", icon=ft.Icons.TASK, on_click=lambda e: open_tool("start taskmgr", "Gerenciador de Tarefas")),
            ft.FilledButton("Visualizador de Eventos", icon=ft.Icons.EVENT, on_click=lambda e: open_tool("start eventvwr", "Visualizador de Eventos")),
            ft.FilledButton("Painel de Controle", icon=ft.Icons.SETTINGS, on_click=lambda e: open_tool("start control", "Painel de Controle")),
            ft.FilledButton("Config. de Rede", icon=ft.Icons.WIFI, on_click=lambda e: open_tool("start ms-settings:network", "Configurações de Rede")),
            ft.FilledButton("Prompt (Admin)", icon=ft.Icons.TERMINAL, on_click=lambda e: open_tool("start cmd", "Prompt de Comando")),
        ], wrap=True, spacing=10),
    ]

    # ------------- Navegação lateral -------------
    content_view = ft.Column(expand=True, spacing=16, controls=[ft.Text("Selecione uma categoria à esquerda."), log_output])

    def set_section(section: str):
        header = ft.Text(f"Categoria: {section}", size=16, weight=ft.FontWeight.BOLD)
        if section == "Rede":
            content_view.controls = [header] + rede_controls + [ft.Divider(), ft.Row([ft.Icon(ft.Icons.SAVE_ALT), ft.Text("Exportar LOG para arquivo")]), ft.ElevatedButton("Salvar LOG", icon=ft.Icons.SAVE, on_click=save_log), log_output]
        elif section == "Sistema":
            content_view.controls = [header] + sistema_controls + [ft.Divider(), ft.ElevatedButton("Salvar LOG", icon=ft.Icons.SAVE, on_click=save_log), log_output]
        elif section == "Ferramentas":
            content_view.controls = [header] + ferramentas_controls + [ft.Divider(), ft.ElevatedButton("Salvar LOG", icon=ft.Icons.SAVE, on_click=save_log), log_output]
        else:
            content_view.controls = [header, ft.Text("Em breve."), log_output]
        page.update()

    nav = ft.NavigationRail(
        selected_index=0,
        label_type=ft.NavigationRailLabelType.ALL,
        extended=False,
        min_width=72,
        min_extended_width=200,
        group_alignment=-0.8,
        destinations=[
            ft.NavigationRailDestination(icon=ft.Icons.ROUTER, label="Rede"),
            ft.NavigationRailDestination(icon=ft.Icons.DESKTOP_WINDOWS, label="Sistema"),
            ft.NavigationRailDestination(icon=ft.Icons.BUILD_CIRCLE, label="Ferramentas"),
        ],
        on_change=lambda e: set_section(["Rede", "Sistema", "Ferramentas"][e.control.selected_index]),
    )

    # Inicializa na seção Rede
    set_section("Rede")

    page.add(
        ft.Row(
            [
                nav,
                ft.VerticalDivider(width=1),
                ft.Container(content_view, expand=True, padding=ft.padding.all(12)),
            ],
            expand=True,
        )
    )

    append_log("Aplicação iniciada. Selecione comandos para executar.")


if __name__ == "__main__":
    # Executa como app de desktop (Flet)
    ft.app(target=main)
