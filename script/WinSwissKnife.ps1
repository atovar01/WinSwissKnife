<#
.SYNOPSIS
    WinSwissKnife.ps1 - Suite de Mantenimiento Profesional para Windows.
.DESCRIPTION
    Una herramienta de PowerShell con interfaz tipo Dashboard, diseñada para el diagnóstico,
    limpieza, optimización, reparación y seguridad de sistemas Windows 10 y 11.
.VERSION
    5.1.0 (Versión Estable - Manejo de Claves de Registro sin Nombre)
.AUTHOR
    Asistente de Programación (Generado por IA)
.NOTES
    Requiere ejecución con privilegios de Administrador.
    Para una correcta visualización, se recomienda usar Windows Terminal en pantalla completa.
#>

#region Globales y Configuración

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Este script requiere privilegios de Administrador." -ForegroundColor Red; exit 1
}

$LogFile = Join-Path -Path $env:TEMP -ChildPath "WinSwissKnife_Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$Global:ObsoleteRegistryScanResult = $null
$Global:LogBuffer = New-Object System.Collections.Generic.List[string]
$Global:LogPanelHeight = 12
$Global:SystemState = $null
$script:currentMenu = 'main'
$ColorTitle = 'Green'; $ColorWarning = 'Yellow'; $ColorError = 'Red'; $ColorInfo = 'Cyan'; $ColorSuccess = 'Green'; $ColorBorder = 'DarkGray'

#endregion

#region Funciones de Utilidad y Dibujo

function Start-LogFile { try { "INICIO DE SESIÓN: $(Get-Date)" | Out-File -FilePath $LogFile -Encoding utf8 } catch { Write-Host "ERROR: No se pudo crear log." -F $ColorError } }
function Write-ToLogFile { param([string]$Message) ; Add-Content -Path $LogFile -Value "[$([DateTime]::Now.ToString('HH:mm:ss'))] $Message" }
function Set-CursorPosition { param($X, $Y) ; try { [Console]::SetCursorPosition($X, $Y) } catch {} }
function Clean-Screen { Clear-Host }

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS','RAW')][string]$Level = 'INFO')
    $prefix = switch ($Level) { 'INFO' {"[INFO] "}; 'WARN' {"[AVISO] "}; 'ERROR' {"[ERROR] "}; 'SUCCESS' {"[ÉXITO] "}; 'RAW' {""} }
    $fullMessage = "$prefix$Message"
    $Global:LogBuffer.Add($fullMessage); Write-ToLogFile $fullMessage; Redraw-LogPanel
}

function Draw-Box {
    param($X, $Y, $Width, $Height, $Title)
    Set-CursorPosition $X $Y; Write-Host "+$('-' * ($Width-2))+" -F $ColorBorder
    for ($i=1; $i -lt ($Height-1); $i++) { Set-CursorPosition $X ($Y+$i); Write-Host "¦" -F $ColorBorder; Set-CursorPosition ($X+$Width-1) ($Y+$i); Write-Host "¦" -F $ColorBorder }
    Set-CursorPosition $X ($Y+$Height-1); Write-Host "+$('-' * ($Width-2))+" -F $ColorBorder
    if ($Title) { Set-CursorPosition ($X + 2) $Y; Write-Host " $Title " -F $ColorTitle }
}

function Clear-LogPanel {
    $logArea = 1..($Global:LogPanelHeight-2); foreach($i in $logArea){ Set-CursorPosition 2 (20+$i); Write-Host (' ' * 114) }
}

function Redraw-LogPanel {
    Clear-LogPanel
    $start = [math]::Max(0, $Global:LogBuffer.Count - ($Global:LogPanelHeight-2)); $lines = $Global:LogBuffer.GetRange($start, $Global:LogBuffer.Count - $start)
    for($i=0; $i -lt $lines.Count; $i++){
        Set-CursorPosition 3 (21+$i); $line = $lines[$i]
        $color = if($line.Contains("[ERROR]")){$ColorError}elseif($line.Contains("[AVISO]")){$ColorWarning}elseif($line.Contains("[ÉXITO]")){$ColorSuccess}else{$ColorInfo}
        Write-Host $line.Substring(0, [math]::Min($line.Length, 113)) -F $color
    }
}

function Show-PaginatedOutput {
    param([Parameter(Mandatory=$true)][string[]]$Content, [Parameter(Mandatory=$true)][string]$Title)
    if ($null -eq $Content -or $Content.Count -eq 0) {
        Write-Log "No se encontró información para mostrar o la lista está vacía." -Level WARN
        Start-Sleep -Seconds 2
        return
    }
    $pageSize = $Global:LogPanelHeight - 2; $pageCount = [math]::Ceiling($Content.Count / $pageSize)
    for ($page = 1; $page -le $pageCount; $page++) {
        Clear-LogPanel; Draw-Box -X 1 -Y 20 -Width 118 -Height $Global:LogPanelHeight -Title "$Title (Página $page de $pageCount)"
        $startIndex = ($page - 1) * $pageSize; $endIndex = [math]::Min($startIndex + $pageSize - 1, $Content.Count - 1)
        $pageContent = $Content[$startIndex..$endIndex]
        for($i=0; $i -lt $pageContent.Length; $i++){ Set-CursorPosition 3 (21+$i); Write-Host $pageContent[$i].Substring(0, [math]::Min($pageContent[$i].Length, 113)) -F $ColorInfo }
        Set-CursorPosition 3 32; Write-Host "Presione una tecla para continuar..." -F $ColorWarning; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown"); Set-CursorPosition 3 32; Write-Host (' ' * 50)
    }
}

function Draw-Dashboard {
    Clean-Screen; Draw-Box -X 1 -Y 1 -Width 58 -Height 18 -Title "ESTADO DEL SISTEMA"
    $menu = $MenuDefinitions[$script:currentMenu]; Draw-Box -X 60 -Y 1 -Width 58 -Height 18 -Title $menu.Title
    Draw-Box -X 1 -Y 20 -Width 118 -Height $Global:LogPanelHeight -Title "SALIDA DE COMANDOS / LOG"
    Fill-SystemStatePanel; Fill-MenuPanel; Redraw-LogPanel
}

function Fill-SystemStatePanel {
    $Y = 2; Set-CursorPosition 3 $Y; Write-Host "Nombre Dispositivo: $($Global:SystemState.DeviceName)"
    $Y = $Y + 2; Set-CursorPosition 3 $Y; Write-Host "SO:               $($Global:SystemState.OS)"
    Set-cursorPosition 3 ($Y+1); Write-Host "Versión:          $($Global:SystemState.OSVersion)"
    Set-CursorPosition 3 ($Y+2); Write-Host "Fecha Instalación:  $($Global:SystemState.OSInstallDate)"
    Set-CursorPosition 3 ($Y+3); Write-Host "Arquitectura:     $($Global:SystemState.OSArch)"
    $Y = $Y + 5; Set-CursorPosition 3 $Y; Write-Host "Procesador: $($Global:SystemState.CPUName.Substring(0, [math]::Min($Global:SystemState.CPUName.Length, 43)))"
    Set-CursorPosition 3 ($Y+1); Write-Host "RAM Total:  $($Global:SystemState.TotalRAM) GB"
    $Y = $Y + 3; Set-CursorPosition 3 $Y; Write-Host "--- Discos Físicos ---"
    $diskY = $Y + 1; foreach($disk in $Global:SystemState.DiskInfo) { if ($diskY -lt 17) { Set-CursorPosition 5 $diskY; Write-Host "Disco $($disk.Number) ($($disk.Type)): $($disk.Name.Substring(0, [math]::Min($disk.Name.Length, 30)))"; $diskY++ } }
}

function Fill-MenuPanel {
    $menu = $MenuDefinitions[$script:currentMenu]; $Y=3
    foreach($item in $menu.Items){ if($Y -lt 17){ Set-CursorPosition 63 $Y; Write-Host $item; $Y++ } }
}

#endregion

#region Precálculo de Información del Sistema

Function Initialize-SystemState {
    Clean-Screen; Write-Host "Cargando información del sistema, por favor espera..." -F $ColorWarning
    $deviceName, $osName, $osArch, $cpuName = "Error al obtener"; $osVersion, $osInstallDate, $totalRam = "N/A"; $diskInfo = @([PSCustomObject]@{Name="Error al obtener discos"; Type="Error"; Number=0})
    try {
        $csInfo = Get-ComputerInfo; $deviceName = $csInfo.CsName; $osName = $csInfo.WindowsProductName; $osBuild = [int]($csInfo.OsBuildNumber)
        if ($osBuild -ge 22000 -and $osName -like '*Windows 10*') { $osName = $osName -replace 'Windows 10', 'Windows 11' }
        $osVersion = $csInfo.OsDisplayVersion; $osArch = $csInfo.OsArchitecture; $cpuNameValue = ($csInfo.CsProcessors).Name
        if (-not [string]::IsNullOrEmpty($cpuNameValue)) { $cpuName = $cpuNameValue }; $totalRam = [math]::Round($csInfo.CsTotalPhysicalMemory / 1GB, 2)
    } catch { Write-ToLogFile "ERROR en Get-ComputerInfo: $($_.Exception.Message)" }
    try {
        $osCimInfo = Get-CimInstance Win32_OperatingSystem; $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($osCimInfo.InstallDate); $osInstallDate = $installDate.ToString('yyyy-MM-dd HH:mm')
    } catch { Write-ToLogFile "ERROR en Get-CimInstance para fecha: $($_.Exception.Message)" }
    try {
        $diskInfoResult = Get-Disk | Where-Object { $_.PartitionStyle -ne 'RAW' } | ForEach-Object {
            $finalMediaType = $_.MediaType; if ([string]::IsNullOrEmpty($finalMediaType) -or $finalMediaType -eq 'Unspecified') { if ($_.FriendlyName -like '*SSD*') { $finalMediaType = 'SSD' } elseif ($_.FriendlyName -like '*HDD*') { $finalMediaType = 'HDD' } else { $finalMediaType = 'Desconocido' } }
            [PSCustomObject]@{ Number = $_.Number; Name = $_.FriendlyName; Type = $finalMediaType }
        }; if ($diskInfoResult) { $diskInfo = $diskInfoResult }
    } catch { Write-ToLogFile "ERROR en Get-Disk: $($_.Exception.Message)" }
    $Global:SystemState = [PSCustomObject]@{ DeviceName = $deviceName; OS = $osName; OSVersion = $osVersion; OSInstallDate = $osInstallDate; OSArch = $osArch; CPUName = $cpuName; TotalRAM = $totalRam; DiskInfo = $diskInfo }
}

#endregion

#region Módulos de Acciones

# MÓDULO 1
function Invoke-QuickSystemCheck { Write-Log "Iniciando diagnóstico rápido..."; $report = @(); if (($Global:SystemState.DiskInfo | Where-Object { $_.Number -eq 0 }).Type -eq 'HDD') { $report += "- El disco de sistema (0) es un HDD. Considere actualizar a un SSD." }; $tempSize = (Get-ChildItem -Path $env:TEMP -Recurse -Force -EA 0 | Measure-Object -Property Length -Sum).Sum / 1MB; if ($tempSize -gt 500) { $report += "- Hay más de 500MB de archivos temporales. Se recomienda una limpieza (Opción 2.2)." }; if ((Get-ComputerRestorePoint -EA 0).Count -eq 0) { $report += "- No existen puntos de restauración. Se recomienda crear uno (Opción 7.2.2)." }; if ($report.Count -gt 0) { Show-PaginatedOutput -Content $report -Title "REPORTE DE DIAGNÓSTICO" } else { Write-Log "El sistema parece estar en buen estado." -Level SUCCESS } }
# MÓDULO 2
function Invoke-AutomatedCleanup { Write-Log "Iniciando limpieza general..."; Invoke-TempFileCleanup; Invoke-RecycleBinClear; Write-Log "Limpieza automatizada completada." -Level SUCCESS }
function Invoke-TempFileCleanup { Write-Log "Calculando tamaño de archivos temporales..."; $tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp"); $tempFiles = Get-ChildItem -Path $tempPaths -Recurse -Force -EA 0; $totalSize = ($tempFiles | Measure-Object -Property Length -Sum).Sum; Write-Log "Limpiando archivos temporales..."; try { $tempFiles | Remove-Item -Recurse -Force -EA 0; Write-Log "$([math]::Round($totalSize / 1MB, 2)) MB de archivos temporales eliminados." -Level SUCCESS } catch { Write-Log "Error al limpiar temporales." -Level ERROR } }
function Invoke-BrowserCleanup { param([string]$Browser, [string]$DataType); Write-Log "AVISO: Para una limpieza efectiva, CIERRA el navegador '$Browser' antes de continuar." -Level WARN; Write-Log "Continuando en 5 segundos..."; Start-Sleep -Seconds 5; $profilePath = ""; switch ($Browser) { 'Edge' { $profilePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" }; 'Chrome' { $profilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" }; 'Firefox' { $profilePath = (Resolve-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release" -EA 0 | Select-Object -First 1).Path } }; if (-not (Test-Path $profilePath)) { Write-Log "Perfil de $Browser no encontrado en la ruta estándar." -Level ERROR; Start-Sleep -Seconds 2; return }; $pathsToDelete = New-Object System.Collections.Generic.List[string]; if ($DataType -in @('Cache', 'All')) { if ($Browser -in @('Edge', 'Chrome')) { $pathsToDelete.Add((Join-Path $profilePath "Cache")) } elseif ($Browser -eq 'Firefox') { $pathsToDelete.Add((Join-Path $profilePath "cache2")) } }; if ($DataType -in @('Cookies', 'All')) { if ($Browser -in @('Edge', 'Chrome')) { $pathsToDelete.Add((Join-Path $profilePath "Network\Cookies")) } elseif ($Browser -eq 'Firefox') { $pathsToDelete.Add((Join-Path $profilePath "cookies.sqlite")) } }; if ($DataType -in @('History', 'All')) { if ($Browser -in @('Edge', 'Chrome')) { $pathsToDelete.Add((Join-Path $profilePath "History")) } elseif ($Browser -eq 'Firefox') { $pathsToDelete.Add((Join-Path $profilePath "places.sqlite")) } }; if ($pathsToDelete.Count -eq 0) { Write-Log "No se especificó un tipo de dato válido." -Level WARN; Start-Sleep -Seconds 2; return }; Write-Log "Calculando tamaño..."; $totalSize = (Get-ChildItem -Path $pathsToDelete -Recurse -Force -EA 0 | Measure-Object -Property Length -Sum).Sum; try { Remove-Item -Path $pathsToDelete -Recurse -Force -EA 0; Write-Log "Limpieza de '$DataType' para '$Browser' completada. Se liberaron $([math]::Round($totalSize / 1MB, 2)) MB." -Level SUCCESS } catch { Write-Log "Error al eliminar datos de $Browser." -Level ERROR }; Start-Sleep -Seconds 2 }
function Invoke-RecycleBinClear { Write-Log "Calculando tamaño de la Papelera..."; $shell = New-Object -ComObject Shell.Application; $recycleBin = $shell.Namespace(10); $size = ($recycleBin.Items() | ForEach-Object { $_.Size } | Measure-Object -Sum).Sum; Write-Log "Vaciando Papelera de Reciclaje..."; try { Clear-RecycleBin -Force -ErrorAction Stop; Write-Log "Papelera vaciada. Se recuperaron $([math]::Round($size / 1MB, 2)) MB." -Level SUCCESS } catch { Write-Log "No se pudo vaciar la papelera." -Level WARN } }
# MÓDULO 3
function Invoke-DiskOptimization {
    Clean-Screen
    Write-Log "Iniciando optimización de unidades..."
    $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
    # Debug: Mostrar detalles de cada disco en SystemState.DiskInfo
    Write-Log "[DEBUG] SystemState DiskInfo contiene $($Global:SystemState.DiskInfo.Count) entradas:" -Level RAW
    foreach ($disk in $Global:SystemState.DiskInfo) {
        Write-Log "[DEBUG] Num: $($disk.Number), Tipo: $($disk.Type), Nombre: $($disk.Name)" -Level RAW
    }
    foreach ($vol in $volumes) {
        $driveLetter = $vol.DriveLetter
        $diskNum = [int]$vol.DiskNumber
        Write-Log "[DEBUG] Procesando volumen $driveLetter (DiskNum: $diskNum)" -Level RAW
        try {
            # Forzar comparación numérica
            $diskState = $Global:SystemState.DiskInfo | Where-Object { [int]$_.Number -eq $diskNum }
            if (-not $diskState) {
                Write-Log "Sin estado para disco $driveLetter (DiskNum: $diskNum). Omitiendo." -Level WARN
                continue
            }
            $action = if ($diskState.Type -eq 'SSD') { 'TRIM' } else { 'Defrag' }
            Write-Log "Ejecutando $action en la unidad $driveLetter..."
            if ($action -eq 'TRIM') {
                Optimize-Volume -DriveLetter $driveLetter -ReTrim -ErrorAction Stop -Verbose `
                    | ForEach-Object { Write-Log $_ }
            } else {
                Optimize-Volume -DriveLetter $driveLetter -Defrag -ErrorAction Stop -Verbose `
                    | ForEach-Object { Write-Log $_ }
            }
            Write-Log "$action completado en unidad $driveLetter" -Level SUCCESS
        } catch {
            Write-Log "Error optimizando unidad $($driveLetter): $($_.Exception.Message)" -Level ERROR
        }
    }
    Pause-UX
}
function Manage-StartupApps { param($Action); if($Action -eq 'list'){ Write-Log "Buscando en múltiples ubicaciones..."; $locations = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"); $output = foreach ($loc in $locations) { Get-ItemProperty $loc -EA 0 | Get-Member -MemberType NoteProperty | ForEach-Object { "- $($_.Name) [Registro]" }}; $startupFolders = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"); $output += Get-ChildItem -Path $startupFolders -EA 0 | ForEach-Object { "- $($_.Name) [Carpeta]" }; Show-PaginatedOutput -Content $output -Title "PROGRAMAS DE INICIO" } if($Action -eq 'open'){ Write-Log "Abriendo Administrador de Tareas..."; taskmgr /0 /startup } }
function Set-HighPerformancePlan { Write-Log "Estableciendo plan de 'Máximo rendimiento'..."; $plan = powercfg /LIST | Where-Object { $_ -match "Máximo rendimiento" }; if ($plan) { $guid = ($plan -split " ")[3]; powercfg /SETACTIVE $guid; Write-Log "Plan de energía establecido." -Level SUCCESS } else { Write-Log "No se encontró el plan de energía." -Level ERROR } }
function Set-PerformanceVisualEffects { Write-Log "Abriendo configuración de efectos visuales..."; SystemPropertiesPerformance.exe }
function Manage-BackgroundApps { Write-Log "Abriendo configuración de apps en segundo plano..."; Start-Process "ms-settings:privacy-backgroundapps" }
# MÓDULO 4
function Invoke-SFC { Write-Log "Iniciando SFC /scannow..."; $output = (sfc.exe /scannow | Out-String).Split([Environment]::NewLine); Show-PaginatedOutput -Content $output -Title "RESULTADO DE SFC" }
function Invoke-DISM { Write-Log "Iniciando DISM..."; $output = (Dism.exe /Online /Cleanup-Image /ScanHealth | Out-String).Split([Environment]::NewLine); Show-PaginatedOutput -Content $output -Title "RESULTADO DE DISM" }
function Schedule-Chkdsk { Write-Log "Programando CHKDSK en C: para el próximo reinicio..."; chkntfs.exe /c C:; Write-Log "Comprobación de disco programada." -Level SUCCESS }
function Diagnose-Drivers { Write-Log "Buscando dispositivos con problemas..."; $devices = Get-CimInstance Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }; if ($devices) { $output = $devices | ForEach-Object { "Problema en: $($_.Name) (Error: $($_.ConfigManagerErrorCode))" }; Show-PaginatedOutput -Content $output -Title "DRIVERS CON PROBLEMAS" } else { Write-Log "No se encontraron dispositivos con errores." -Level SUCCESS } }
# MÓDULO 5
function Start-DefenderScan { param($Type); Write-Log "Iniciando escaneo de Microsoft Defender ($Type)..."; try { Start-MpScan -ScanType $Type; Write-Log "Comando de escaneo enviado." -Level SUCCESS } catch { Write-Log "No se pudo iniciar el escaneo." -Level ERROR } }
function Manage-Firewall { param($Action); if ($Action -eq 'status') { $output = Get-NetFirewallProfile | ForEach-Object { "Firewall ($($_.Name)): $($_.Enabled)" }; Show-PaginatedOutput -Content $output -Title "ESTADO DEL FIREWALL" } if ($Action -eq 'reset') { Write-Log "Restaurando políticas de firewall..." -Level WARN; netsh advfirewall reset | Out-Null; Write-Log "Firewall restaurado." -Level SUCCESS } }
function Network-Tools { param($Action); $commandOutput = switch($Action){ 'dns' {ipconfig /flushdns}; 'tcp' {netsh int ip reset}; 'ip' {ipconfig /release; ipconfig /renew} }; $output = ($commandOutput | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 }); Show-PaginatedOutput -Content $output -Title "RESULTADO DEL COMANDO DE RED" }
function Show-HostsFile { try { $output = Get-Content "$env:SystemRoot\system32\drivers\etc\hosts"; Show-PaginatedOutput -Content $output -Title "CONTENIDO DEL ARCHIVO HOSTS" } catch { Write-Log "Error al leer el archivo hosts: $($_.Exception.Message)" -Level ERROR } }
# MÓDULO 6
function Show-FullSystemReport { Write-Log "Generando reporte..."; try { $output = $Global:SystemState | Format-List | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 }; Show-PaginatedOutput -Content $output -Title "REPORTE COMPLETO DEL SISTEMA" } catch { Write-Log "Error al generar el reporte: $($_.Exception.Message)" -Level ERROR } }
function Analyze-DiskSpace { Write-Log "Analizando C: (Top 10)... Puede tardar MUCHO."; try { $output = Get-ChildItem -Path C:\ -Directory -EA 0 | ForEach-Object { $_ | Add-Member -Name Size -Value (Get-ChildItem -Path $_.FullName -Recurse -Force -EA 0 | Measure-Object -Property Length -Sum).Sum -PassThru } | Sort-Object Size -Descending | Select-Object -First 10 | ForEach-Object { "$([math]::Round($_.Size / 1GB, 2)) GB -> $($_.FullName)" }; Show-PaginatedOutput -Content $output -Title "ANÁLISIS DE ESPACIO" } catch { Write-Log "Error analizando el espacio." -Level ERROR } }
function Get-Uptime { $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; Write-Log "Tiempo de actividad: $($uptime.Days)d, $($uptime.Hours)h, $($uptime.Minutes)m." }
function List-InstalledSoftware { Write-Log "Generando lista de software..."; try { $output = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA 0 | Select-Object DisplayName, DisplayVersion | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DisplayName) } | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 }; Show-PaginatedOutput -Content $output -Title "SOFTWARE INSTALADO" } catch { Write-Log "Error al generar la lista: $($_.Exception.Message)" -Level ERROR } }
function List-ProcessesByCpu { Write-Log "Generando lista de procesos..."; try { $output = Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name, Id, CPU, WS | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 }; Show-PaginatedOutput -Content $output -Title "PROCESOS POR CPU" } catch { Write-Log "Error al generar la lista: $($_.Exception.Message)" -Level ERROR } }
function List-ProcessesByMemory { Write-Log "Generando lista de procesos..."; try { $output = Get-Process | Sort-Object WS -Descending | Select-Object -First 30 Name, Id, CPU, WS | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 }; Show-PaginatedOutput -Content $output -Title "PROCESOS POR MEMORIA (WS)" } catch { Write-Log "Error al generar la lista: $($_.Exception.Message)" -Level ERROR } }
# MÓDULO 7
function Backup-FullRegistry { Write-Log "Crear respaldo puede tardar y ocupar espacio." -Level WARN; $backupPath = "$env:USERPROFILE\Desktop\RegistryBackup_$(Get-Date -Format 'yyyy-MM-dd-HHmm').reg"; Write-Log "El respaldo se guardará en: $backupPath"; Set-CursorPosition 3 32; $confirmation = Read-Host "¿Continuar? (S/N)"; if ($confirmation.ToUpper() -ne 'S') { Write-Log "Operación cancelada." -Level WARN; return }; Write-Log "Iniciando respaldo..."; try { reg.exe export HKLM "$backupPath" /y; Write-Log "Respaldo completado." -Level SUCCESS } catch { Write-Log "Error durante el respaldo: $($_.Exception.Message)" -Level ERROR } }
function Scan-ObsoleteRegistryKeys {
    Write-Log "Buscando claves de software obsoleto..."
    try {
        $locations = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $found = @()
        foreach ($loc in $locations) {
            Get-ItemProperty -Path $loc -EA 0 | ForEach-Object {
                if ($_.InstallLocation -and -not (Test-Path $_.InstallLocation)) {
                    $found += [PSCustomObject]@{DisplayName = $_.DisplayName; Path = $_.PSPath }
                }
            }
        }
        if ($found.Count -gt 0) {
            Write-Log "$($found.Count) claves obsoletas encontradas." -Level WARN
            $Global:ObsoleteRegistryScanResult = $found
            # Construir lista de ghost entries garantizando contenido válido
            $displayList = @()
            foreach ($item in $found) {
                # Nombre o etiqueta inteligente
                if (-not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                    $displayList += "- $($item.DisplayName)"
                } else {
                    $keyName = Split-Path -Path $item.Path -Leaf
                    $displayList += "- [ENTRADA SIN NOMBRE] ($keyName)"
                }
                # Ruta de la clave
                $displayList += "  Ruta: $($item.Path)"
            }
            # Mostrar lista de ghost entries
            if ($displayList.Count -gt 0) {
                Show-PaginatedOutput -Content $displayList -Title "CLAVES FANTASMA (Obsoletas)"
            } else {
                Write-Log "No se encontraron ghost entries para mostrar." -Level WARN
            }
        } else {
            Write-Log "No se encontraron claves obsoletas." -Level SUCCESS
            $Global:ObsoleteRegistryScanResult = $null
        }
    } catch {
        Write-Log "Se produjo un error crítico durante el escaneo del registro." -Level ERROR
        Write-Log ("Error: " + $_.Exception.Message) -Level ERROR
        Start-Sleep -Seconds 3
    }
}
function Clean-ObsoleteRegistryKeys { 
    if ($null -eq $Global:ObsoleteRegistryScanResult) { Write-Log "Debes escanear (Opción 7.1.3) antes de limpiar." -Level WARN; return }
    $backupDir = Join-Path -Path $env:TEMP -ChildPath "RegBackups_$(Get-Date -Format 'yyyyMMddHHmmss')"; New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-Log "Se creará un respaldo de cada clave eliminada en $backupDir" -Level WARN
    foreach ($key in $Global:ObsoleteRegistryScanResult) {
        # Lógica de formateo inteligente para mostrar la clave a eliminar
        $displayNameToShow = $key.DisplayName
        if ([string]::IsNullOrWhiteSpace($displayNameToShow)) {
            $keyName = Split-Path -Path $key.Path -Leaf
            $displayNameToShow = "[ENTRADA SIN NOMBRE] ($keyName)"
        }
        Write-Log "Clave: $displayNameToShow" -Level INFO
        Write-Log "Ruta: $($key.Path)" -Level RAW
        Set-CursorPosition 3 32
        $choice = Read-Host "¿Eliminar esta clave? (S/N)"
        if ($choice.ToUpper() -eq 'S') {
            $keyNameForFile = ($key.Path | Split-Path -Leaf) -replace '[^a-zA-Z0-9]', '_'; $backupFile = Join-Path -Path $backupDir -ChildPath "$($keyNameForFile).reg"
            try {
                reg.exe export "$($key.Path)" "$backupFile" /y; Write-Log "Respaldo de clave creado" -Level SUCCESS
                Remove-Item -Path $key.Path -Recurse -Force; Write-Log "Clave eliminada." -Level SUCCESS
            } catch { Write-Log "ERROR al procesar clave: $($_.Exception.Message)" -Level ERROR }
        } else { Write-Log "Clave omitida por el usuario." }
    }
    $Global:ObsoleteRegistryScanResult = $null
}
function Manage-RestorePoints { param($Action); if ($Action -eq 'list') { $output = (Get-ComputerRestorePoint | Format-Table -AutoSize | Out-String).Split([Environment]::NewLine); Show-PaginatedOutput -Content $output -Title "PUNTOS DE RESTAURACIÓN" } if ($Action -eq 'create') { Write-Log "Creando punto de restauración..."; try { Checkpoint-Computer -Description "WinSwissKnife Backup" } catch { Write-Log "Error al crear punto de restauración: $($_.Exception.Message)" -Level ERROR } } }
function Open-EnvironmentVariables { Write-Log "Abriendo editor de variables de entorno..."; SystemPropertiesAdvanced.exe }

#endregion

#region Definiciones de Menú

$MenuDefinitions = @{
    main = [PSCustomObject]@{ Title = "MENÚ PRINCIPAL"; Items = @("1. Diagnóstico Rápido y Recomendaciones", "2. Módulo de Limpieza Profunda", "3. Módulo de Optimización", "4. Módulo de Salud y Reparación", "5. Módulo de Seguridad y Redes", "6. Módulo de Información y Reportes", "7. Módulo de Herramientas Avanzadas", "Q. Salir"); Actions = @{ '1' = { Invoke-QuickSystemCheck }; '2' = { $script:currentMenu = 'cleanup' }; '3' = { $script:currentMenu = 'optimization' }; '4' = { $script:currentMenu = 'health' }; '5' = { $script:currentMenu = 'security' }; '6' = { $script:currentMenu = 'info' }; '7' = { $script:currentMenu = 'advanced' }; 'Q' = { exit } } }
    cleanup = [PSCustomObject]@{ Title = "LIMPIEZA PROFUNDA"; Items = @("2.1 Limpieza General Automatizada", "2.2 Limpiar Archivos Temporales", "2.3 Limpieza de Navegadores", "2.5 Vaciar Papelera de Reciclaje", "V. Volver al Menú Principal"); Actions = @{ '2.1' = { Invoke-AutomatedCleanup }; '2.2' = { Invoke-TempFileCleanup }; '2.3' = { $script:currentMenu = 'browserCleanup' }; '2.5' = { Invoke-RecycleBinClear }; 'V' = { $script:currentMenu = 'main' } } }
    browserCleanup = [PSCustomObject]@{ Title = "LIMPIEZA DE NAVEGADORES"; Items = @("Detectando navegadores..."); Actions = @{ 'V' = { $script:currentMenu = 'cleanup'} } }
    optimization = [PSCustomObject]@{ Title = "OPTIMIZACIÓN"; Items = @("3.1 Optimizar Unidades (TRIM/Defrag)", "3.2.1 Listar Programas de Inicio", "3.2.2 Abrir Administrador de Tareas", "3.3 Establecer Plan 'Máximo Rendimiento'", "3.4 Ajustar Efectos Visuales", "3.5 Abrir Apps en Segundo Plano", "V. Volver"); Actions = @{ '3.1' = { Invoke-DiskOptimization }; '3.2.1' = { Manage-StartupApps 'list' }; '3.2.2' = { Manage-StartupApps 'open' }; '3.3' = { Set-HighPerformancePlan }; '3.4' = { Set-PerformanceVisualEffects }; '3.5' = { Manage-BackgroundApps }; 'V' = { $script:currentMenu = 'main' } } }
    health = [PSCustomObject]@{ Title = "SALUD Y REPARACIÓN"; Items = @("4.1 Verificación Básica (SFC)", "4.2 Reparación Avanzada (DISM)", "4.3 Programar Comprobación de Disco", "4.5 Diagnóstico de Controladores", "V. Volver"); Actions = @{ '4.1' = { Invoke-SFC }; '4.2' = { Invoke-DISM }; '4.3' = { Schedule-Chkdsk }; '4.5' = { Diagnose-Drivers }; 'V' = { $script:currentMenu = 'main' } } }
    security = [PSCustomObject]@{ Title = "SEGURIDAD Y REDES"; Items = @("5.1.1 Escaneo Rápido (Defender)", "5.1.2 Escaneo Completo (Defender)", "5.2.1 Mostrar Estado del Firewall", "5.2.2 Restaurar Políticas del Firewall", "5.3.1 Limpiar Caché de DNS", "5.3.2 Reiniciar Pila TCP/IP", "5.3.3 Liberar y Renovar IP", "5.4 Revisar Archivo 'Hosts'", "V. Volver"); Actions = @{ '5.1.1' = { Start-DefenderScan 'QuickScan' }; '5.1.2' = { Start-DefenderScan 'FullScan' }; '5.2.1' = { Manage-Firewall 'status' }; '5.2.2' = { Manage-Firewall 'reset' }; '5.3.1' = { Network-Tools 'dns' }; '5.3.2' = { Network-Tools 'tcp' }; '5.3.3' = { Network-Tools 'ip' }; '5.4' = { Show-HostsFile }; 'V' = { $script:currentMenu = 'main' } } }
    info = [PSCustomObject]@{ Title = "INFORMACIÓN Y REPORTES"; Items = @("6.1 Resumen Completo del Sistema", "6.2 Análisis de Espacio en Disco (LENTO)", "6.3 Reporte de Tiempo de Actividad", "6.4 Listar Todo el Software Instalado", "6.5 Listar Procesos por CPU", "6.6 Listar Procesos por Memoria", "V. Volver"); Actions = @{ '6.1' = { Show-FullSystemReport }; '6.2' = { Analyze-DiskSpace }; '6.3' = { Get-Uptime }; '6.4' = { List-InstalledSoftware }; '6.5' = { List-ProcessesByCpu }; '6.6' = { List-ProcessesByMemory }; 'V' = { $script:currentMenu = 'main' } } }
    advanced = [PSCustomObject]@{ Title = "HERRAMIENTAS AVANZADAS"; Items = @("7.1 Herramientas del Registro", "7.2 Herramientas de Restauración", "7.3 Abrir Variables de Entorno", "V. Volver"); Actions = @{ '7.1' = { $script:currentMenu = 'registryTools' }; '7.2' = { $script:currentMenu = 'restorePoints' }; '7.3' = { Open-EnvironmentVariables }; 'V' = { $script:currentMenu = 'main' } } }
    registryTools = [PSCustomObject]@{ Title = "HERRAMIENTAS DEL REGISTRO"; Items = @("7.1.1 Crear Respaldo COMPLETO del Registro", "7.1.3 Escanear Entradas Obsoletas", "7.1.4 Limpiar Entradas (Interactivo)", "V. Volver"); Actions = @{ '7.1.1' = { Backup-FullRegistry }; '7.1.3' = { Scan-ObsoleteRegistryKeys }; '7.1.4' = { Clean-ObsoleteRegistryKeys }; 'V' = { $script:currentMenu = 'advanced' } } }
    restorePoints = [PSCustomObject]@{ Title = "PUNTOS DE RESTAURACIÓN"; Items = @("7.2.1 Listar Puntos de Restauración", "7.2.2 Crear Nuevo Punto de Restauración", "V. Volver"); Actions = @{ '7.2.1' = { Manage-RestorePoints 'list' }; '7.2.2' = { Manage-RestorePoints 'create' }; 'V' = { $script:currentMenu = 'advanced' } } }
}

#endregion

#region Bucle Principal

function Start-MainExecution {
    Start-LogFile

    $possibleBrowserPaths = @{
        Edge = @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe", "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe");
        Chrome = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe");
        Firefox = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$env:ProgramFiles(x86)\Mozilla Firefox\firefox.exe")
    }
    $detectedBrowsers = $possibleBrowserPaths.GetEnumerator() | Where-Object { $pathExists = $false; foreach($path in $_.Value){ if(Test-Path $path){$pathExists = $true; break}}; $pathExists } | ForEach-Object { $_.Name }
    if ($detectedBrowsers) {
        $bItems = @(); $bActions = @{}; $i = 1
        foreach ($browser in $detectedBrowsers) {
            $bItems += "--- Limpieza para $browser ---";
            $bItems += "2.3.$($i) Limpiar Cache";     $bActions["2.3.$i"] = [scriptblock]::Create("Invoke-BrowserCleanup -Browser '$browser' -DataType 'Cache'"); $i++
            $bItems += "2.3.$($i) Limpiar Cookies";   $bActions["2.3.$i"] = [scriptblock]::Create("Invoke-BrowserCleanup -Browser '$browser' -DataType 'Cookies'"); $i++
            $bItems += "2.3.$($i) Limpiar Historial"; $bActions["2.3.$i"] = [scriptblock]::Create("Invoke-BrowserCleanup -Browser '$browser' -DataType 'History'"); $i++
        }
        $bItems += "V. Volver al Menú Principal"; $bActions['V'] = { $script:currentMenu = 'cleanup' }
        $MenuDefinitions.browserCleanup.Items = $bItems; $MenuDefinitions.browserCleanup.Actions = $bActions
    } else {
        $MenuDefinitions.cleanup.Actions['2.3'] = { Write-Log "No se detectaron navegadores compatibles (Edge, Chrome, Firefox)." -Level WARN }
    }
    
    Initialize-SystemState

    while ($true) {
        Draw-Dashboard
        Set-CursorPosition 3 32; Write-Host (' ' * 70) -NoNewline; Set-CursorPosition 3 32
        $choice = Read-Host "Selecciona una opción y presiona Enter"
        
        Set-CursorPosition 3 32; Write-Host (' ' * 70)
        
        $menu = $MenuDefinitions[$script:currentMenu]
        if ($menu.Actions.ContainsKey($choice.ToUpper())) {
            & $menu.Actions[$choice.ToUpper()]
        }
        else {
            Write-Log "Opción no válida: '$choice'." -Level WARN; Start-Sleep -Seconds 1
        }
    }
}

#endregion

# =================================================================================
# PUNTO DE ENTRADA DEL SCRIPT
# =================================================================================
Start-MainExecution