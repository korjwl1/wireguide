Unicode true

####
## Please note: Template replacements don't work in this file. They are provided with default defines like
## mentioned underneath.
## If the keyword is not defined, "wails_tools.nsh" will populate them.
## If they are defined here, "wails_tools.nsh" will not touch them. This allows you to use this project.nsi manually
## from outside of Wails for debugging and development of the installer.
## 
## For development first make a wails nsis build to populate the "wails_tools.nsh":
## > wails build --target windows/amd64 --nsis
## Then you can call makensis on this file with specifying the path to your binary:
## For a AMD64 only installer:
## > makensis -DARG_WAILS_AMD64_BINARY=..\..\bin\app.exe
## For a ARM64 only installer:
## > makensis -DARG_WAILS_ARM64_BINARY=..\..\bin\app.exe
## For a installer with both architectures:
## > makensis -DARG_WAILS_AMD64_BINARY=..\..\bin\app-amd64.exe -DARG_WAILS_ARM64_BINARY=..\..\bin\app-arm64.exe
####
## The following information is taken from the wails_tools.nsh file, but they can be overwritten here.
## These !defines are evaluated before the !include below, so they win over the
## wails-generated fallbacks in wails_tools.nsh — which lets us hand-pick branding
## without editing the "DO NOT EDIT" generated file.
####
!define INFO_COMPANYNAME    "korjwl1"
!define INFO_PRODUCTNAME    "WireGuide"
!define INFO_COPYRIGHT      "© 2026 korjwl1"
# UNINST_KEY_NAME drives the registry key under Uninstall\ and the "Programs and
# Features" display. Default is "${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" =
# "korjwl1WireGuide", which is awkward — override to the clean product name.
!define UNINST_KEY_NAME     "WireGuide"
####
## !define INFO_PROJECTNAME    "my-project" # Default "wireguide"
## !define INFO_PRODUCTVERSION "1.0.0"     # Default "0.1.0"
###
## !define PRODUCT_EXECUTABLE  "Application.exe"      # Default "${INFO_PROJECTNAME}.exe"
####
## !define REQUEST_EXECUTION_LEVEL "admin"            # Default "admin"  see also https://nsis.sourceforge.io/Docs/Chapter4.html
####
## Include the wails tools
####
!include "wails_tools.nsh"

# The version information for this two must consist of 4 parts
VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"

VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

# Enable HiDPI support. https://nsis.sourceforge.io/Reference/ManifestDPIAware
ManifestDPIAware true

!include "MUI.nsh"

!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
# !define MUI_WELCOMEFINISHPAGE_BITMAP "resources\leftimage.bmp" #Include this to add a bitmap on the left side of the Welcome Page. Must be a size of 164x314
!define MUI_FINISHPAGE_NOAUTOCLOSE # Wait on the INSTFILES page so the user can take a look into the details of the installation steps
!define MUI_ABORTWARNING # This will warn the user if they exit from the installer.

!insertmacro MUI_PAGE_WELCOME # Welcome to the installer page.
# !insertmacro MUI_PAGE_LICENSE "resources\eula.txt" # Adds a EULA page to the installer
!insertmacro MUI_PAGE_DIRECTORY # In which folder install page.
!insertmacro MUI_PAGE_INSTFILES # Installing page.
!insertmacro MUI_PAGE_FINISH # Finished installation page.

!insertmacro MUI_UNPAGE_INSTFILES # Uninstalling page

!insertmacro MUI_LANGUAGE "English" # Set the Language of the installer

## The following two statements can be used to sign the installer and the uninstaller. The path to the binaries are provided in %1
#!uninstfinalize 'signtool --file "%1"'
#!finalize 'signtool --file "%1"'

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe" # Name of the installer's file.
# Single folder under Program Files — the wails default "<company>\<product>" nests
# "korjwl1\WireGuide" which is ugly when company is just a github handle.
InstallDir "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
ShowInstDetails show # This will always show the installation details.

Function .onInit
   !insertmacro wails.checkArchitecture
FunctionEnd

Section
    !insertmacro wails.setShellContext

    !insertmacro wails.webview2runtime

    SetOutPath $INSTDIR

    !insertmacro wails.files

    # wireguard-go loads wintun.dll dynamically from the EXE directory at first
    # TUN creation. Bundled here by `task vendor:wintun` during build.
    File "..\..\..\bin\wintun.dll"

    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"
    CreateShortCut "$DESKTOP\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"

    # Put the install dir on the system PATH so `wireguide ctl ...` is
    # callable from any terminal (the same binary is the GUI and the CLI).
    # Done via PowerShell/.NET rather than raw NSIS registry edits: .NET
    # reads and writes the full PATH value (NSIS's ReadRegStr truncates at
    # 1024 chars and would corrupt a long PATH), skips if already present,
    # and broadcasts WM_SETTINGCHANGE so new shells pick it up.
    #
    # $INSTDIR is passed to PowerShell as a PROCESS ENVIRONMENT VARIABLE,
    # never interpolated into the script source — a user-chosen install
    # path can legally contain a single quote, which would otherwise break
    # out of a PowerShell string literal and run as code under the
    # installer's admin token. `"` can't appear in a Windows path, so the
    # SetEnvironmentVariable marshalling below is safe. $$x is an escaped
    # literal `$x` for PowerShell.
    System::Call 'kernel32::SetEnvironmentVariable(t "WIREGUIDE_DIR", t "$INSTDIR")'
    nsExec::ExecToLog `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$d=$$env:WIREGUIDE_DIR; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if(($$p -split ';') -notcontains $$d){[Environment]::SetEnvironmentVariable('Path',$$p.TrimEnd(';')+';'+$$d,'Machine')}"`
    Pop $0
    ${If} $0 != 0
        DetailPrint "Note: could not add WireGuide to PATH (exit $0). Use the full path to wireguide.exe, or add it to PATH manually."
    ${EndIf}

    !insertmacro wails.associateFiles
    !insertmacro wails.associateCustomProtocols
    
    !insertmacro wails.writeUninstaller
SectionEnd

Section "uninstall" 
    !insertmacro wails.setShellContext

    RMDir /r "$AppData\${PRODUCT_EXECUTABLE}" # Remove the WebView2 DataPath

    # Remove the install dir from the system PATH (mirror of the install
    # step; $INSTDIR passed via env var, not interpolated — see install).
    System::Call 'kernel32::SetEnvironmentVariable(t "WIREGUIDE_DIR", t "$INSTDIR")'
    nsExec::ExecToLog `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$d=$$env:WIREGUIDE_DIR; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); $$n=(($$p -split ';') | Where-Object { $$_ -ne $$d }) -join ';'; [Environment]::SetEnvironmentVariable('Path',$$n,'Machine')"`

    RMDir /r $INSTDIR

    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    !insertmacro wails.deleteUninstaller
SectionEnd
