import flet as ft
import subprocess
import threading
import sys
import re
import os
from datetime import datetime

# ------------------------------
# Utilidades
# ------------------------------

def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Relança o próprio app como Administrador (UAC)."""
    try:
        import ctypes
        if is_admin():
            return True
        params = f'"{os.path.abspath(__file__)}"'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return True
    except Exception:
        return False


def run_cmd(cmd: str, use_powershell: bool = False, timeout: int = 240) -> tuple[int, str]:
    """Executa um comando no Windows e retorna (returncode, saida+erros)."""
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
                f"{cmd} | Out-String",
            ]
            proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "") + f"\n(ReturnCode={proc.returncode})"
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        return 1, f"Tempo excedido executando: {cmd}"
    except Exception as e:
        return 1, f"Erro ao executar comando: {e}"


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------
# App Flet
# ------------------------------

def main(page: ft.Page):
    page.title = "Suporte N2 - Windows Toolkit (v3)"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.window_min_height = 760
    page.window_min_width = 1180

    admin = is_admin()

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

    def run_in_thread(fn, *args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True).start()

    # --- Runner PowerShell com saída em tempo real no "terminal" (log_output)
    def stream_ps(title: str, ps_cmd: str):
        def task():
            append_log(f"Iniciando: {title}")
            args = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy","Bypass",
                "-Command", ps_cmd
            ]
            try:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                if proc.stdout:
                    for line in proc.stdout:
                        log_output.value += line
                        page.update()
                rc = proc.wait()
                append_log(f"Finalizado: {title} (ReturnCode={rc})")
            except Exception as e:
                append_log(f"Erro no streaming: {e}")
        run_in_thread(task)

    # ------------- Campos de entrada -------------
    host_field = ft.TextField(label="Host/IP", hint_text="ex.: 8.8.8.8 ou dominio.com", width=260)
    port_field = ft.TextField(label="Porta (opcional)", hint_text="ex.: 443", width=120)
    pid_field = ft.TextField(label="PID", hint_text="ex.: 1234", width=120)
    drive_field = ft.TextField(label="Unidade", hint_text="ex.: C:", width=100)
    folder_field = ft.TextField(label="Pasta", hint_text="ex.: C:\\Users\\Public", width=360)
    topn_field = ft.TextField(label="Top N", hint_text="ex.: 20", width=100)
    group_field = ft.TextField(label="Grupo local", hint_text='ex.: "Administrators"', width=240)
    dell_path_field = ft.TextField(label="Dell Command Update (exe)", hint_text=r"ex.: C:\\Program Files\\Dell\\CommandUpdate\\DellCommandUpdate.exe", width=520)
    profile_script_field = ft.TextField(label="Script Replicação (PS1) — opcional", hint_text=r"ex.: C:\\Temp\\replicar_perfil.ps1", width=520)

    admin_badge = ft.Container(
        content=ft.Row([
            ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS, color=ft.Colors.GREEN if admin else ft.Colors.RED),
            ft.Text("Admin: SIM" if admin else "Admin: NÃO — alguns comandos (netsh/chkdsk) podem falhar.")
        ]),
        padding=ft.padding.symmetric(8, 8),
    )

    # ------------- Rede -------------
    def do_ipconfig_all(e=None):
        run_in_thread(lambda: append_block("ipconfig /all", run_cmd("ipconfig /all")[1]))

    def do_ping(e=None):
        host = host_field.value.strip()
        if not host:
            return append_log("Informe um host antes de pingar.")
        run_in_thread(lambda: append_block(f"ping {host}", run_cmd(f"ping -n 4 {host}")[1]))

    def do_tracert(e=None):
        host = host_field.value.strip()
        if not host:
            return append_log("Informe um host antes de executar o tracert.")
        run_in_thread(lambda: append_block(f"tracert {host}", run_cmd(f"tracert {host}")[1]))

    def do_nslookup(e=None):
        host = host_field.value.strip()
        if not host:
            return append_log("Informe um host/domínio antes de executar o nslookup.")
        run_in_thread(lambda: append_block(f"nslookup {host}", run_cmd(f"nslookup {host}")[1]))

    def do_test_port(e=None):
        host, port = host_field.value.strip(), port_field.value.strip()
        if not host or not port:
            return append_log("Informe host e porta para testar conectividade TCP.")
        run_in_thread(lambda: append_block(
            f"Test-NetConnection {host}:{port}",
            run_cmd(f"Test-NetConnection -ComputerName '{host}' -Port {port}", use_powershell=True)[1]
        ))

    def do_release(e=None):
        run_in_thread(lambda: append_block("ipconfig /release", run_cmd("ipconfig /release")[1]))

    def do_renew(e=None):
        run_in_thread(lambda: append_block("ipconfig /renew", run_cmd("ipconfig /renew")[1]))

    def do_reset_tcpip(e=None):
        run_in_thread(lambda: append_block("netsh int ip reset", run_cmd("netsh int ip reset")[1]))

    def do_reset_winsock(e=None):
        run_in_thread(lambda: append_block("netsh winsock reset", run_cmd("netsh winsock reset")[1]))

    # ------------- Sistema -------------
    def do_systeminfo(e=None):
        run_in_thread(lambda: append_block("systeminfo", run_cmd("systeminfo")[1]))

    def do_uptime(e=None):
        ps = (
            "$lb=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;"
            "$ts=(Get-Date)-$lb;"
            '"LastBoot: {0}\nUptime: {1:dd\\ d\\ hh\\ h\\ mm\\ m\\ ss\\ s}" -f $lb,$ts'
        )
        run_in_thread(lambda: append_block("Uptime (CIM)", run_cmd(ps, use_powershell=True)[1]))

    def do_last_boot_wmic(e=None):
        def parse_wmic_time(raw: str):
            m = re.search(r"LastBootUpTime=([0-9]{14})", raw)
            if not m:
                return None
            s = m.group(1)
            try:
                return datetime.strptime(s, "%Y%m%d%H%M%S")
            except Exception:
                return None
        def fmt_tdelta(td):
            total = int(td.total_seconds())
            d, rem = divmod(total, 86400)
            h, rem = divmod(rem, 3600)
            m, s = divmod(rem, 60)
            return f"{d} d {h:02} h {m:02} m {s:02} s"
        def task():
            append_log("Obtendo LastBoot via WMIC...")
            rc, out = run_cmd("wmic os get lastbootuptime /value")
            boot = parse_wmic_time(out)
            if not boot:
                append_block("WMIC LastBootUpTime", out)
                return
            now = datetime.now()
            uptime = now - boot
            body = (
                f"LastBoot (WMIC): {boot.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Uptime: {fmt_tdelta(uptime)}\n\n"
                f"Saída bruta:\n{out}"
            )
            append_block("Última Inicialização (WMIC)", body)
        run_in_thread(task)

    # ------------- Processos -------------
    def do_list_processes(e=None):
        ps = (
            "Get-Process | Sort-Object CPU -Descending | "
            "Select-Object -First 30 Name,Id,CPU,WS,PM | Format-Table -AutoSize"
        )
        run_in_thread(lambda: append_block("Processos (Top 30 por CPU)", run_cmd(ps, use_powershell=True)[1]))

    def do_kill_pid(e=None):
        pid = (pid_field.value or "").strip()
        if not pid.isdigit():
            return append_log("Informe um PID numérico para finalizar.")
        run_in_thread(lambda: append_block(f"taskkill /PID {pid} /F", run_cmd(f"taskkill /PID {pid} /F")[1]))

    # ------------- Disco -------------
    def do_list_disks(e=None):
        ps = (
            'Get-CimInstance Win32_LogicalDisk | '
            'Select-Object DeviceID,DriveType,VolumeName,'
            '@{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},'
            '@{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}} | '
            'Format-Table -AutoSize'
        )
        run_in_thread(lambda: append_block("Discos (LogicalDisk)", run_cmd(ps, use_powershell=True)[1]))

    def do_chkdsk(e=None):
        drv = (drive_field.value or "").strip() or "C:"
        ps = f"chkdsk {drv}"
        stream_ps(f"CHKDSK {drv} (stream)", ps)

    def do_list_large_files(e=None):
        folder = (folder_field.value or "").strip()
        n = (topn_field.value or "20").strip()
        if not folder:
            return append_log("Informe a pasta para listar arquivos grandes.")
        ps = (
            f"Get-ChildItem -LiteralPath '{folder}' -Recurse -ErrorAction SilentlyContinue | "
            "Where-Object { -not $_.PSIsContainer } | "
            "Sort-Object Length -Descending | "
            f"Select-Object -First {n} FullName,@{{Name='SizeMB';Expression={{[math]::Round($_.Length/1MB,2)}}}} | "
            "Format-Table -AutoSize"
        )
        run_in_thread(lambda: append_block(f"Top {n} maiores arquivos em {folder}", run_cmd(ps, use_powershell=True)[1]))

    # ------------- Usuários/Grupos (locais) -------------
    def do_list_local_users(e=None):
        run_in_thread(lambda: append_block("Usuários locais", run_cmd("net user")[1]))

    def do_list_local_groups(e=None):
        run_in_thread(lambda: append_block("Grupos locais", run_cmd("net localgroup")[1]))

    def do_group_members(e=None):
        grp = (group_field.value or "").strip()
        if not grp:
            return append_log("Informe o nome do grupo local (ex.: Administrators).")
        run_in_thread(lambda: append_block(f"Membros do grupo '{grp}'", run_cmd(f'net localgroup "{grp}"')[1]))

    # ------------- Quality (ONS) -------------
    def do_diag_report(e=None):
        # Streaming no terminal enquanto gera o relatório
        ps = (
            "Write-Host 'Coletando informações do sistema...';"
            "$os = Get-CimInstance Win32_OperatingSystem;"
            "$cs = Get-CimInstance Win32_ComputerSystem;"
            "$cpu = Get-CimInstance Win32_Processor;"
            "$mem = Get-CimInstance Win32_PhysicalMemory;"
            "$disk = Get-CimInstance Win32_DiskDrive;"
            "$bios = Get-CimInstance Win32_BIOS;"
            "Write-Host 'Verificando Secure Boot/TPM...';"
            "$sb = try { (Confirm-SecureBootUEFI) } catch { 'Desconhecido' };"
            "$tpm = try { Get-TPM } catch { $null };"
            "Write-Host 'Montando conteúdo...';"
            "$lines = @();"
            "$lines += 'Computador: ' + $cs.Name;"
            "$lines += 'Fabricante/Modelo: ' + ($cs.Manufacturer + ' / ' + $cs.Model);"
            "$lines += 'OS: ' + $os.Caption + ' ' + $os.Version;"
            "$lines += 'BIOS: ' + $bios.SMBIOSBIOSVersion + ' (' + $bios.ReleaseDate + ')';"
            "$lines += 'CPU: ' + $cpu.Name + ' (' + $cpu.NumberOfCores + 'C/' + $cpu.NumberOfLogicalProcessors + 'T)';"
            "$lines += 'RAM Total(GB): ' + [math]::Round(($cs.TotalPhysicalMemory/1GB),2);"
            "$lines += 'Slots RAM: ' + ($mem | Measure-Object).Count;"
            "$lines += 'SecureBoot: ' + $sb;"
            "$lines += 'TPM Presente: ' + ([bool]($tpm -ne $null));"
            "$lines += 'Discos:';"
            "$disk | ForEach-Object { $lines += ('  - ' + $_.Model + ' | ' + $_.InterfaceType + ' | ' + [math]::Round($_.Size/1GB,2) + ' GB') };"
            "Write-Host 'Gravando arquivo em C\\Temp...';"
            "$path = 'C\\Temp'; if(-not (Test-Path $path)){ New-Item -ItemType Directory -Path $path | Out-Null };"
            "$file = Join-Path $path ('Relatorio_' + (Get-Date -Format yyyyMMdd_HHmmss) + '.txt');"
            "$lines | Set-Content -Path $file -Encoding UTF8;"
            "Write-Host ('Relatório salvo em: ' + $file);"
        )
        stream_ps("Relatório de Diagnóstico (stream)", ps)

    def do_secure_channel_repair(e=None):
        # Abre uma janela do PowerShell elevada e interativa para credenciais (sem streaming interno)
        cmd = (
            "Start-Process powershell -Verb runAs -ArgumentList "
            "'-NoProfile -ExecutionPolicy Bypass -Command "
            "Test-ComputerSecureChannel -Repair -Credential (Get-Credential); Read-Host \"Pressione ENTER para sair\"'"
        )
        run_in_thread(lambda: append_block("Reparar Canal Seguro AD", run_cmd(cmd, use_powershell=True)[1]))

    def do_enable_rdp(e=None):
        # Habilita Área de Trabalho Remota e libera no firewall
        ps = (
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0; "
            "Enable-NetFirewallRule -DisplayGroup 'Área de Trabalho Remota'"
        )
        stream_ps("Habilitar Área de Trabalho Remota (RDP)", ps)

    def do_windows_features(e=None):
        run_in_thread(lambda: (subprocess.Popen("optionalfeatures", shell=True), append_log("Recursos do Windows solicitado.")))

    def do_map_network_drive(e=None):
        run_in_thread(lambda: (subprocess.Popen("rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL Connect", shell=True), append_log("Mapear Unidade de Rede solicitado.")))

    def do_quick_assist(e=None):
        run_in_thread(lambda: (subprocess.Popen("quickassist", shell=True), append_log("Quick Assist solicitado.")))

    def do_windows_fix_ps1(e=None):
        path = r"C:\\Temp\\correcao_windows.ps1"
        if not os.path.exists(path):
            return append_log(f"Script não encontrado: {path}")
        # Executa elevado – abrirá outra janela; streaming interno não é possível nessa modalidade
        cmd = f"Start-Process powershell -Verb runAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{path}\"'"
        run_in_thread(lambda: append_block("Correção do Windows (PS1)", run_cmd(cmd, use_powershell=True)[1]))

    def do_profiles_acl_fix(e=None):
        def confirmed_run():
            if not is_admin():
                append_log("Precisa estar em modo Administrador para essa ação.")
                return
            # 1) Reaplicar permissões (stream)
            ps_perm = (
                "Write-Host 'Reaplicando permissões em C\\Users (takeown/icacls)...';"
                "$base='C:\\Users';"
                "Get-ChildItem $base -Directory | ForEach-Object {"
                "  try {"
                "    takeown /F $_.FullName /R /D Y | Out-Null;"
                "    icacls $_.FullName /grant *S-1-5-32-544:F /T /C | Out-Null;"
                "    Write-Host ('OK: ' + $_.FullName)"
                "  } catch { Write-Host ('Falha: ' + $_.FullName) }"
                "}"
            )
            stream_ps("Reaplicar Permissões em Perfis (stream)", ps_perm)
            # 2) Se houver script de replicação, executar em seguida (stream)
            p = (profile_script_field.value or "").strip()
            if p and os.path.exists(p):
                stream_ps("Executando Script de Replicação", f"-ExecutionPolicy Bypass -File \"{p}\"")
            elif p:
                append_log(f"Script informado não encontrado: {p}")
        # diálogo de confirmação
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Atenção"),
            content=ft.Text("Esta ação altera permissões em C\\Users e pode executar um script de replicação, se informado."),
            actions=[
                ft.TextButton("Cancelar", on_click=lambda e: (setattr(dlg, "open", False), page.update())),
                ft.TextButton("Continuar (Admin)", on_click=lambda e: (setattr(dlg, "open", False), page.update(), confirmed_run())),
            ],
        )
        page.dialog = dlg
        dlg.open = True
        page.update()

    def do_winget_upgrade(e=None):
        # Saída em tempo real no log_output
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Write-Host 'Resetando fontes do WinGet...'; winget source reset --force;"
            "Write-Host 'Atualizando fontes do WinGet...'; winget source update;"
            "Write-Host 'Atualizando todos os pacotes...'; winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements -h 0"
        )
        stream_ps("WinGet Upgrade (stream)", ps)

    def do_relaunch_admin(e=None):
        ok = relaunch_as_admin()
        if ok:
            append_log("Solicitada elevação. Se nada acontecer, execute como Administrador.")
        else:
            append_log("Falha ao solicitar elevação (UAC).")

    def do_dell_command(e=None):
        # Tenta caminhos padrão e, se falhar, usa o caminho do campo de texto
        default_paths = [
            r"C:\\Program Files\\Dell\\CommandUpdate\\DellCommandUpdate.exe",
            r"C:\\Program Files (x86)\\Dell\\CommandUpdate\\DellCommandUpdate.exe",
            r"C:\\Program Files\\Dell\\SupportAssistAgent\\bin\\SupportAssistUI.exe",
        ]
        custom_path = (dell_path_field.value or "").strip()
        candidates = [p for p in default_paths if os.path.exists(p)]
        if custom_path:
            candidates.insert(0, custom_path)
        if not candidates:
            append_log("Dell Command/SupportAssist não encontrado. Informe o caminho no campo acima.")
            return
        path = candidates[0]
        def task():
            append_log(f"Abrindo Dell utilitário: {path}")
            try:
                subprocess.Popen(f'"{path}"', shell=True)
                append_log("Dell utilitário solicitado.")
            except Exception as e:
                append_log(f"Falha ao abrir Dell utilitário: {e}")
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

    # ------------- Controles (UI) -------------
    rede_controls = [
        ft.Row([host_field, port_field], alignment=ft.MainAxisAlignment.START),
        admin_badge,
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
            ft.ElevatedButton("UPTIME (CIM)", icon=ft.Icons.ACCESS_TIME, on_click=do_uptime),
            ft.ElevatedButton("LAST BOOT (WMIC)", icon=ft.Icons.HISTORY, on_click=do_last_boot_wmic),
        ], wrap=True, spacing=10),
    ]

    processos_controls = [
        ft.Row([
            ft.ElevatedButton("Listar Processos (CPU)", icon=ft.Icons.LIST, on_click=do_list_processes),
            pid_field,
            ft.OutlinedButton("Encerrar PID", icon=ft.Icons.CANCEL, on_click=do_kill_pid),
        ], wrap=True, spacing=10),
    ]

    disco_controls = [
        ft.Row([
            ft.ElevatedButton("Listar Discos", icon=ft.Icons.STORAGE, on_click=do_list_disks),
            drive_field,
            ft.OutlinedButton("CHKDSK", icon=ft.Icons.BUILD, on_click=do_chkdsk),
        ], wrap=True, spacing=10),
        ft.Row([
            folder_field,
            topn_field,
            ft.OutlinedButton("Top arquivos grandes", icon=ft.Icons.FOLDER, on_click=do_list_large_files),
        ], wrap=True, spacing=10),
    ]

    usuarios_controls = [
        ft.Row([
            ft.ElevatedButton("Listar Usuários Locais", icon=ft.Icons.PERSON, on_click=do_list_local_users),
            ft.ElevatedButton("Listar Grupos Locais", icon=ft.Icons.GROUPS, on_click=do_list_local_groups),
        ], wrap=True, spacing=10),
        ft.Row([
            group_field,
            ft.OutlinedButton("Ver membros do grupo", icon=ft.Icons.GROUP, on_click=do_group_members),
        ], wrap=True, spacing=10),
    ]

    quality_controls = [
        ft.Text("Quality (ONS)", weight=ft.FontWeight.BOLD),
        profile_script_field,
        ft.Row([
            ft.FilledButton("Relatório de Diagnóstico (TXT)", icon=ft.Icons.DESCRIPTION, on_click=do_diag_report),
            ft.FilledButton("Reparar Canal Seguro AD", icon=ft.Icons.VPN_LOCK, on_click=do_secure_channel_repair),
            ft.FilledButton("Atualizar Programas (WinGet)", icon=ft.Icons.SYSTEM_UPDATE_ALT, on_click=do_winget_upgrade),
        ], wrap=True, spacing=10),
        ft.Row([
            ft.OutlinedButton("Correção do Windows (PS1)", icon=ft.Icons.BUILD, on_click=do_windows_fix_ps1),
            ft.OutlinedButton("Reaplicar Permissões (Perfis) + Script", icon=ft.Icons.ADMIN_PANEL_SETTINGS, on_click=do_profiles_acl_fix),
        ], wrap=True, spacing=10),
        ft.Row([
            dell_path_field,
            ft.OutlinedButton("Abrir Dell Command/SupportAssist", icon=ft.Icons.DEVICE_HUB, on_click=do_dell_command),
            ft.OutlinedButton("Habilitar RDP (Win 10/11)", icon=ft.Icons.DESKTOP_WINDOWS, on_click=do_enable_rdp),
            ft.OutlinedButton("Recursos do Windows", icon=ft.Icons.EXTENSION, on_click=do_windows_features),
            ft.OutlinedButton("Mapear Unidade de Rede", icon=ft.Icons.DRIVE_FILE_MOVE, on_click=do_map_network_drive),
            ft.OutlinedButton("Quick Assist", icon=ft.Icons.SUPPORT_AGENT, on_click=do_quick_assist),
            ft.OutlinedButton("Reiniciar como Admin", icon=ft.Icons.SECURITY, on_click=do_relaunch_admin),
        ], wrap=True, spacing=10),
    ]

    # ------------- Navegação -------------
    content_view = ft.Column(expand=True, spacing=16, controls=[ft.Text("Selecione uma categoria à esquerda."), log_output])

    def set_section(section: str):
        header = ft.Text(f"Categoria: {section}", size=16, weight=ft.FontWeight.BOLD)
        mapping = {
            "Rede": rede_controls,
            "Sistema": sistema_controls,
            "Processos": processos_controls,
            "Disco": disco_controls,
            "Usuários": usuarios_controls,
            "Quality (ONS)": quality_controls,
        }
        if section in mapping:
            content_view.controls = [header] + mapping[section] + [ft.Divider(), ft.ElevatedButton("Salvar LOG", icon=ft.Icons.SAVE, on_click=save_log), log_output]
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
            ft.NavigationRailDestination(icon=ft.Icons.MEMORY, label="Processos"),
            ft.NavigationRailDestination(icon=ft.Icons.STORAGE, label="Disco"),
            ft.NavigationRailDestination(icon=ft.Icons.PEOPLE, label="Usuários"),
            ft.NavigationRailDestination(icon=ft.Icons.FACT_CHECK, label="Quality (ONS)"),
        ],
        on_change=lambda e: set_section(["Rede", "Sistema", "Processos", "Disco", "Usuários", "Quality (ONS)"][e.control.selected_index]),
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
    ft.app(target=main)
