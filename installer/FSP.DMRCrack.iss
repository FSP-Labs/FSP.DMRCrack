; FSP.DMRCrack Installer Script
; Builds: FSP.DMRCrack-<version>-Setup.exe
;
; To compile: open in Inno Setup Compiler and press Build (Ctrl+F9)

#define MyAppName      "FSP.DMRCrack"
; MyAppVersion can be overridden from CLI: ISCC /DMyAppVersion="0.2.0" ...
#ifndef MyAppVersion
  #define MyAppVersion "0.1.2"
#endif
#define MyAppPublisher "FSP-Labs"
#define MyAppURL       "https://github.com/FSP-Labs"
#define MyAppExeName   "dmrcrack.exe"
#define MyAppDesc      "GPU-accelerated ARC4 key recovery for DMR Enhanced Privacy"

[Setup]
AppId={{2A488B07-B170-4487-B268-6C2D4C83D9BF}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppComments={#MyAppDesc}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir=output
OutputBaseFilename=FSP.DMRCrack-{#MyAppVersion}-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
WizardImageFile=wizard_side.bmp
WizardSmallImageFile=wizard_small.bmp
DisableProgramGroupPage=yes
PrivilegesRequired=admin
MinVersion=10.0
LicenseFile=..\LICENSE
; Version info shown in Add/Remove Programs
AppContact={#MyAppURL}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppDesc}
VersionInfoCompany={#MyAppPublisher}
VersionInfoCopyright=Copyright (C) 2026 {#MyAppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
WelcomeLabel1=Welcome to the {#MyAppName} {#MyAppVersion} Setup Wizard
WelcomeLabel2={#MyAppDesc}.%n%nThis wizard will install {#MyAppName} on your computer, including the DSD-FME demodulator and all required runtime libraries.%n%nClick Next to continue, or Cancel to exit the installer.

[Components]
Name: "main";  Description: "FSP.DMRCrack core (GPU brute-force engine + DSD-FME demodulator)"; Types: full; Flags: fixed
Name: "tools"; Description: "Conversion scripts (Python 3 required)"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; === Core application ===
Source: "..\bin\{#MyAppExeName}";  DestDir: "{app}"; Components: main; Flags: ignoreversion

; WinSparkle auto-update library
Source: "..\vendor\winsparkle\x64\WinSparkle.dll"; DestDir: "{app}"; Components: main; Flags: ignoreversion

; CUDA runtime DLLs (included only when present next to the executable)
Source: "..\bin\cudart64_*.dll"; DestDir: "{app}"; Components: main; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\bin\*.dll";          DestDir: "{app}"; Components: main; Flags: ignoreversion skipifsourcedoesntexist

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Components: main; Flags: ignoreversion
Source: "..\LICENSE";   DestDir: "{app}"; Components: main; Flags: ignoreversion
Source: "..\NOTICE";    DestDir: "{app}"; Components: main; Flags: ignoreversion

; === Conversion scripts ===
Source: "..\tools\dsdfme_dsp_to_bin.py";             DestDir: "{app}\tools"; Components: tools; Flags: ignoreversion
Source: "..\tools\extract_encrypted_from_dsdfme.bat"; DestDir: "{app}\tools"; Components: tools; Flags: ignoreversion
Source: "..\tools\verify_decrypt.py";                DestDir: "{app}\tools"; Components: tools; Flags: ignoreversion

; === DSD-FME demodulator + all required Cygwin runtime DLLs ===
Source: "..\tools\dsd-fme.exe"; DestDir: "{app}\tools"; Components: main; Flags: ignoreversion
Source: "..\tools\cyg*.dll";    DestDir: "{app}\tools"; Components: main; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";                    Filename: "{app}\{#MyAppExeName}"; Comment: "{#MyAppDesc}"
Name: "{group}\Uninstall {#MyAppName}";          Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; Comment: "{#MyAppDesc}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox(
      '{#MyAppName} requires Windows 10/11 (64-bit).' + #13#10 +
      'This installer cannot continue.',
      mbError, MB_OK
    );
    Result := False;
  end;
end;
