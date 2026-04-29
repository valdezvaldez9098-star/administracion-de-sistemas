# ============================================================
# PRACTICA 8 - Script 03: AppLocker
# Bloqueo/permiso de Bloc de Notas por grupo via GPO
# Ejecutar como Administrador en PowerShell en el DC
# ============================================================

param(
    [string]$DomainName = "practica8.local"
)

function Write-Log {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "[AppLocker] $Msg" -ForegroundColor $Color
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

$DomainDN = (Get-ADDomain).DistinguishedName

# ============================================================
# BLOQUE 1: Verificar/Instalar Application Identity Service
# ============================================================
Write-Log "Verificando servicio Application Identity (AppIDSvc)..."

$Svc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
if ($Svc) {
    Set-Service -Name "AppIDSvc" -StartupType Automatic
    Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    Write-Log "Servicio AppIDSvc configurado como automatico." "Green"
} else {
    Write-Log "ADVERTENCIA: AppIDSvc no encontrado. Asegurate de habilitar AppLocker en los clientes." "Yellow"
}

# ============================================================
# BLOQUE 2: Obtener el HASH del Bloc de Notas
# ============================================================
# En Server Core, notepad puede estar en distintas rutas
$NotepadPaths = @(
    "C:\Windows\System32\notepad.exe",
    "C:\Windows\notepad.exe",
    "C:\Windows\SysWOW64\notepad.exe"
)

$NotepadPath = $null
foreach ($P in $NotepadPaths) {
    if (Test-Path $P) {
        $NotepadPath = $P
        break
    }
}

if (-not $NotepadPath) {
    Write-Log "ADVERTENCIA: notepad.exe no encontrado en este servidor. El hash se obtendra del cliente Windows 10." "Yellow"
    Write-Log "En el cliente Windows 10, ejecuta: Get-AppLockerFileInformation -Path 'C:\Windows\System32\notepad.exe'" "Yellow"
    $NotepadHash = "HASH_PENDIENTE_OBTENER_DEL_CLIENTE"
} else {
    Write-Log "Obteniendo hash de: $NotepadPath"
    $FileInfo = Get-AppLockerFileInformation -Path $NotepadPath
    $NotepadHash = $FileInfo.Hash.HashDataString
    Write-Log "Hash SHA256 de notepad.exe: $NotepadHash" "Green"
}

# ============================================================
# BLOQUE 3: Crear XML de politica AppLocker para CUATES
# (Permiten ejecutar notepad - regla de path)
# ============================================================
Write-Log "Generando XML de politica AppLocker para Cuates..."

$XmlCuates = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Regla por defecto: Admins pueden ejecutar todo -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Todos los archivos ubicados en la carpeta Windows"
                  Description="Permite ejecutar todo en Windows para admins"
                  UserOrGroupSid="S-1-5-32-544"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Todos los archivos ubicados en Archivos de Programa"
                  Description="Admins pueden ejecutar desde Program Files"
                  UserOrGroupSid="S-1-5-32-544"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>

    <!-- Regla especifica: Cuates pueden ejecutar notepad.exe -->
    <FilePathRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                  Name="Cuates - Permitir Bloc de Notas"
                  Description="Permite a Cuates ejecutar notepad.exe"
                  UserOrGroupSid="DOMAIN_CUATES_SID_PLACEHOLDER"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\System32\notepad.exe"/>
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="b9e18c21-ff8f-43cf-b9fc-db40eed693bb"
                  Name="Cuates - Permitir Bloc de Notas SysWOW64"
                  Description="Permite a Cuates ejecutar notepad.exe 32bit"
                  UserOrGroupSid="DOMAIN_CUATES_SID_PLACEHOLDER"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\notepad.exe"/>
      </Conditions>
    </FilePathRule>

  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

# ============================================================
# BLOQUE 4: Crear XML de politica AppLocker para NOCUATES
# (Bloquean notepad por HASH - incluso si se renombra el .exe)
# ============================================================
Write-Log "Generando XML de politica AppLocker para NoCuates (bloqueo por hash)..."

# El SID de NoCuates se resuelve dinamicamente
$SidNoCuates = (Get-ADGroup -Identity "NoCuates").SID.Value
$SidCuates   = (Get-ADGroup -Identity "Cuates").SID.Value

# Reemplazar SID placeholder en XML de Cuates
$XmlCuates = $XmlCuates.Replace("DOMAIN_CUATES_SID_PLACEHOLDER", $SidCuates)

$XmlNoCuates = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Regla por defecto: Admins pueden ejecutar todo -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Todos los archivos ubicados en la carpeta Windows"
                  Description="Permite ejecutar todo en Windows para admins"
                  UserOrGroupSid="S-1-5-32-544"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Todos los archivos ubicados en Archivos de Programa"
                  Description="Admins pueden ejecutar desde Program Files"
                  UserOrGroupSid="S-1-5-32-544"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>

    <!-- BLOQUEO por HASH para NoCuates - aunque renombren el archivo -->
    <FileHashRule Id="c1234567-89ab-cdef-0123-456789abcdef"
                  Name="NoCuates - Bloquear Bloc de Notas por Hash"
                  Description="Bloquea notepad.exe por hash SHA256, sin importar el nombre del archivo"
                  UserOrGroupSid="$SidNoCuates"
                  Action="Deny">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256"
                    Data="$NotepadHash"
                    SourceFileName="notepad.exe"
                    SourceFileLength="0"/>
        </FileHashCondition>
      </Conditions>
    </FileHashRule>

  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

# ============================================================
# BLOQUE 5: Guardar XMLs en disco
# ============================================================
$PathCuates   = "C:\Scripts\AppLocker_Cuates.xml"
$PathNoCuates = "C:\Scripts\AppLocker_NoCuates.xml"

New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null
$XmlCuates   | Out-File -FilePath $PathCuates   -Encoding UTF8
$XmlNoCuates | Out-File -FilePath $PathNoCuates -Encoding UTF8

Write-Log "XMLs guardados en C:\Scripts\" "Green"

# ============================================================
# BLOQUE 6: Crear y vincular GPOs de AppLocker
# ============================================================
Write-Log "Creando GPO AppLocker_Cuates..."
$GPOCuatesName = "AppLocker_Cuates"
if (-not (Get-GPO -Name $GPOCuatesName -ErrorAction SilentlyContinue)) {
    $GPOCuates = New-GPO -Name $GPOCuatesName
} else {
    $GPOCuates = Get-GPO -Name $GPOCuatesName
}

Write-Log "Creando GPO AppLocker_NoCuates..."
$GPONoCuatesName = "AppLocker_NoCuates"
if (-not (Get-GPO -Name $GPONoCuatesName -ErrorAction SilentlyContinue)) {
    $GPONoCuates = New-GPO -Name $GPONoCuatesName
} else {
    $GPONoCuates = Get-GPO -Name $GPONoCuatesName
}

# Aplicar XML a cada GPO usando Set-AppLockerPolicy sobre el GPO
# Nota: Set-AppLockerPolicy aplica localmente; para GPO se usa la ruta del registro dentro del GPO
# Metodo: inyectar la politica en el GPO via archivo ADMX / registro

# Ruta del GPO en SYSVOL
$SysvolBase  = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies"
$GPOCuatesId = $GPOCuates.Id.ToString("B").ToUpper()
$GPONoCuatesId = $GPONoCuates.Id.ToString("B").ToUpper()

$AppLockerPathCuates   = "$SysvolBase\$GPOCuatesId\Machine\Microsoft\Windows NT\AppLocker"
$AppLockerPathNoCuates = "$SysvolBase\$GPONoCuatesId\Machine\Microsoft\Windows NT\AppLocker"

New-Item -ItemType Directory -Path $AppLockerPathCuates   -Force | Out-Null
New-Item -ItemType Directory -Path $AppLockerPathNoCuates -Force | Out-Null

# Aplicar politica AppLocker en los GPOs
# Se usa el cmdlet nativo con -Ldap para apuntar al GPO correcto
Write-Log "Aplicando politica AppLocker al GPO Cuates..."
Set-AppLockerPolicy -XmlPolicy $PathCuates -Ldap "LDAP://CN=$GPOCuatesId,CN=Policies,CN=System,$DomainDN"

Write-Log "Aplicando politica AppLocker al GPO NoCuates..."
Set-AppLockerPolicy -XmlPolicy $PathNoCuates -Ldap "LDAP://CN=$GPONoCuatesId,CN=Policies,CN=System,$DomainDN"

# Vincular GPO Cuates a OU Cuates
$OUCuates   = "OU=Cuates,$DomainDN"
$OUNoCuates = "OU=NoCuates,$DomainDN"

New-GPLink -Name $GPOCuatesName   -Target $OUCuates   -LinkEnabled Yes -ErrorAction SilentlyContinue
New-GPLink -Name $GPONoCuatesName -Target $OUNoCuates -LinkEnabled Yes -ErrorAction SilentlyContinue

Write-Log "GPOs de AppLocker vinculadas a sus UOs." "Green"

# ============================================================
# BLOQUE 7: Habilitar Application Identity en los clientes via GPO
# ============================================================
Write-Log "Configurando servicio AppIDSvc como automatico en GPO..."

Set-GPRegistryValue -Name $GPOCuatesName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" `
    -ValueName "Start" -Type DWord -Value 2

Set-GPRegistryValue -Name $GPONoCuatesName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" `
    -ValueName "Start" -Type DWord -Value 2

# ============================================================
# VERIFICACION
# ============================================================
Write-Log "=== GPOs de AppLocker ===" "Magenta"
Get-GPO -Name $GPOCuatesName   | Select-Object DisplayName, Id, GpoStatus | Format-List
Get-GPO -Name $GPONoCuatesName | Select-Object DisplayName, Id, GpoStatus | Format-List

Write-Log @"

=== INSTRUCCIONES POST-CONFIGURACION ===

1. En el cliente Windows 10, ejecuta 'gpupdate /force'
2. Verifica el servicio: Get-Service AppIDSvc
3. Prueba con usuario de NoCuates: ejecutar notepad -> debe bloquearse
4. Prueba renombrando notepad.exe a 'editor.exe' -> sigue bloqueado por hash
5. Prueba con usuario de Cuates: notepad debe ejecutarse normalmente

Si el hash de notepad es 'HASH_PENDIENTE_OBTENER_DEL_CLIENTE':
   a) En el cliente Win10: Get-AppLockerFileInformation -Path 'C:\Windows\System32\notepad.exe'
   b) Copia el hash y actualiza el XML en C:\Scripts\AppLocker_NoCuates.xml
   c) Vuelve a ejecutar: Set-AppLockerPolicy -XmlPolicy C:\Scripts\AppLocker_NoCuates.xml -Ldap '...'
"@ "Magenta"
