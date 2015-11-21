; NSIS2 Script
; by Alexander Shaduri <ashaduri 'at' gmail.com>.
; Compatible with NSIS Unicode 2.45.
; Public Domain

; pass /DNO_GTK to makensis to disable inclusion of gtk.

!delfile gtk-gnutella.nsh
!macro Script command
  !system '%WD%\sh -c "${command}" >> gtk-gnutella.nsh'
!macroend
!insertmacro Script 'echo -n \"!define PRODUCT_VERSION \"'
!insertmacro Script 'scripts/gtkg-version .'

!insertmacro Script 'echo -n \"!define DLLDIR_GNUTLS \"'
!insertmacro Script 'echo `pkg-config gnutls --libs-only-L | cut -c3- `| \ 
	sed -e s,/lib$,/bin,' 
!insertmacro Script 'echo \"!define MINGW $MINGW\"'

; gtk installer name for embedding
!define GTK_INSTALLER_EXE "gtk2-runtime-2.24.10-2012-10-10-ash.exe"
!include gtk-gnutella.nsh
!define PRODUCT_NAME "gtk-gnutella"
!define PRODUCT_NAME_SMALL "gtk-gnutella"
!define PRODUCT_PUBLISHER "gtk-gnutella developers"
!define PRODUCT_WEB_SITE "http://gtk-gnutella.sourceforge.net"

!define PRODUCT_UNINST_KEY \
	"Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

!define REGISTRY_APP_PATHS \
	"Software\Microsoft\Windows\CurrentVersion\App Paths"


!include "FileFunc.nsh"  ; GetOptions



; --------------- General Settings


; This is needed for proper start menu item manipulation (for all users) in vista
RequestExecutionLevel admin

; This compressor gives us the best results
SetCompressor /SOLID lzma

; Do a CRC check before installing
CRCCheck On

; This is used in titles
Name "${PRODUCT_NAME}  ${PRODUCT_VERSION}"

; Output File Name
!ifdef NO_GTK
	OutFile "${PRODUCT_NAME_SMALL}-${PRODUCT_VERSION}-nogtk.exe"
!else
	OutFile "${PRODUCT_NAME_SMALL}-${PRODUCT_VERSION}.exe"
!endif


; The Default Installation Directory:
; Try to install to the same directory as runtime.
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
; If already installed, try here
InstallDirRegKey HKLM "SOFTWARE\${PRODUCT_NAME}" "InstallationDirectory"


ShowInstDetails show
ShowUnInstDetails show





; --------------------- MUI INTERFACE

; MUI 2.0 compatible install
!include "MUI2.nsh"
!include "InstallOptions.nsh"  ; section description macros

; Backgound Colors. uncomment to enable fullscreen.
; BGGradient 0000FF 000000 FFFFFF

; MUI Settings
!define MUI_ABORTWARNING
;!define MUI_ICON "nsi_install.ico"
;!define MUI_UNICON "nsi_uninstall.ico"


; Things that need to be extracted on first
; (keep these lines before any File command!).
; Only useful for BZIP2 compression.
;!insertmacro MUI_RESERVEFILE_LANGDLL
;!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS


; Language Selection Dialog Settings
;!define MUI_LANGDLL_REGISTRY_ROOT "${PRODUCT_UNINST_ROOT_KEY}"
;!define MUI_LANGDLL_REGISTRY_KEY "${PRODUCT_UNINST_KEY}"
;!define MUI_LANGDLL_REGISTRY_VALUENAME "NSIS:Language"

;!ifdef NO_GTK
;	!define LICENSE_FILE "doc\distribution-nogtk.txt"
;!else
;	!define LICENSE_FILE "doc\distribution.txt"
;!endif
!define LICENSE_FILE "LICENSE"

; Pages to show during installation
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!ifndef NO_GTK
	!define MUI_PAGE_CUSTOMFUNCTION_LEAVE on_components_page_leave
	!insertmacro MUI_PAGE_COMPONENTS
!endif
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

;!define MUI_FINISHPAGE_RUN "$INSTDIR\gtk-gnutella.exe"
;!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\Example.file"
;!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!insertmacro MUI_PAGE_FINISH



; Uninstaller page
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES



; Language files
!insertmacro MUI_LANGUAGE "English"


; --------------- END MUI

LangString TEXT_IO_TITLE ${LANG_ENGLISH} "gtk-gnutella"


; uninstall the old version first (if present)
var install_option_removeold ; yes (default), no.



; ----------------- INSTALLATION TYPES

; InstType "Recommended"
; InstType "Full"
; InstType "Minimal"




Section "!gtk-gnutella" SecMain
SectionIn 1 RO
	SetShellVarContext all  ; use all user variables as opposed to current user
	SetOutPath "$INSTDIR"

	SetOverwrite Off ; don't overwrite the config file

	SetOverwrite On
	File win32\bundle\bin\gtk-gnutella.exe
	File win32\bundle\lib\gtk-gnutella\gtk-gnutella.nm
	File pixmaps\icon.ico

	File ${MINGW}\bin\libiconv-2.dll
	File ${MINGW}\bin\pthreadGC2.dll

	; Include gnutls -- these are for gnutls-3.4.5
	File ${DLLDIR_GNUTLS}\libgnutls-30.dll
	File ${DLLDIR_GNUTLS}\libgcc_s_sjlj-1.dll
	File ${DLLDIR_GNUTLS}\libgmp-10.dll
	File ${DLLDIR_GNUTLS}\libhogweed-4-0.dll
	File ${DLLDIR_GNUTLS}\libnettle-6-0.dll
	File ${DLLDIR_GNUTLS}\libp11-kit-0.dll

	SetOutPath $INSTDIR\share
	File /r win32\bundle\share\*.*
	
	; Include the "doc" directory completely, excluding the file
	; we're not using (e.g. the -nogtk file in gtk installer).
;!ifdef NO_GTK
;	File /r /x distribution.txt doc
;!else
;	File /r /x distribution-nogtk.txt doc
;!endif

	; Add Shortcuts (this inherits the exe's run permissions)
	CreateShortCut "$SMPROGRAMS\gtk-gnutella.lnk" \
		"$INSTDIR\gtk-gnutella.exe" "" \
		"$INSTDIR\icon.ico" "" SW_SHOWNORMAL "" \
		"gtk-gnutella - Gnutella servent"

SectionEnd



!ifndef NO_GTK

; The SecGtkPrivate and SecGtkPublic sections are mutually exclusive.

Section "GTK+ (for this program only)" SecGtkPrivate
	SectionIn 1
	SetShellVarContext all  ; use all user variables as opposed to current user
	AddSize 12200  ; ~ size of unpacked gtk
	SetOutPath "$INSTDIR"
	File "${GTK_INSTALLER_EXE}"
	; TODO: in the future, when we have translations for this program,
	; make the GTK+ translations installation dependent on their installation status.
	ExecWait '"${GTK_INSTALLER_EXE}" /sideeffects=no /dllpath=root /translations=no /compatdlls=no /S /D=$INSTDIR'
	Delete "$INSTDIR\${GTK_INSTALLER_EXE}"
SectionEnd

; disabled by default
Section /o "GTK+ (shared installation)" SecGtkPublic
	SectionIn 1
	SetShellVarContext all  ; use all user variables as opposed to current user
	AddSize 12200  ; ~ size of unpacked gtk
	SetOutPath "$INSTDIR"
	File "${GTK_INSTALLER_EXE}"
	ExecWait '"${GTK_INSTALLER_EXE}"'
	Delete "$INSTDIR\${GTK_INSTALLER_EXE}"
SectionEnd

!endif  ; !NO_GTK


!ifndef NO_GTK
var gtk_mode  ; "public", "private" or "none"
var gtk_tmp  ; temporary variable
!endif


; Executed on installation start
Function .onInit
	SetShellVarContext all  ; use all user variables as opposed to current user

	${GetOptions} "$CMDLINE" "/removeold=" $install_option_removeold

	Call PreventMultipleInstances

	Call DetectPrevInstallation

; ask for gtk only if it's a non-gtk installer.
!ifdef NO_GTK
	Call AskForGtk
!endif

!ifndef NO_GTK
	StrCpy $gtk_mode "private" ; default
!endif

FunctionEnd



function .onselchange

!ifndef NO_GTK
	; Remember which gtk section was selected.
	; Deselect the other section.

	; If it was private, we check if public is checked and uncheck private.

	StrCmp $gtk_mode "private" check_public  ; old selection
	StrCmp $gtk_mode "public" check_private  ; old selection
	goto check_exit

	check_public:
		SectionGetFlags ${SecGtkPublic} $gtk_tmp  ; see if it's checked
		IntOp $gtk_tmp $gtk_tmp & ${SF_SELECTED}
		IntCmp $gtk_tmp ${SF_SELECTED} "" check_exit check_exit
		SectionGetFlags ${SecGtkPrivate} $gtk_tmp  ; unselect the other one
		IntOp $gtk_tmp $gtk_tmp & ${SECTION_OFF}
		SectionSetFlags ${SecGtkPrivate} $gtk_tmp
		goto check_exit

	check_private:
		SectionGetFlags ${SecGtkPrivate} $gtk_tmp  ; see if it's checked
		IntOp $gtk_tmp $gtk_tmp & ${SF_SELECTED}
		IntCmp $gtk_tmp ${SF_SELECTED} "" check_exit check_exit
		SectionGetFlags ${SecGtkPublic} $gtk_tmp  ; unselect the other one
		IntOp $gtk_tmp $gtk_tmp & ${SECTION_OFF}
		SectionSetFlags ${SecGtkPublic} $gtk_tmp

	check_exit:


	; store the current mode
	StrCpy $gtk_mode "none"

	SectionGetFlags ${SecGtkPrivate} $gtk_tmp
	IntOp $gtk_tmp $gtk_tmp & ${SF_SELECTED}
	IntCmp $gtk_tmp ${SF_SELECTED} "" mode_end_private mode_end_private
	StrCpy $gtk_mode "private"
	mode_end_private:

	SectionGetFlags ${SecGtkPublic} $gtk_tmp
	IntOp $gtk_tmp $gtk_tmp & ${SF_SELECTED}
	IntCmp $gtk_tmp ${SF_SELECTED} "" mode_end_public mode_end_public
	StrCpy $gtk_mode "public"
	mode_end_public:

	; MessageBox MB_ICONINFORMATION|MB_OK "gtk_mode: $gtk_mode" /SD IDOK
!endif  ; !NO_GTK

functionend


!ifndef NO_GTK
Function on_components_page_leave
	StrCmp $gtk_mode "none" "" noabort
		Call AskForGtk
	noabort:
FunctionEnd
!endif  ; !NO_GTK




; Section descriptions
!ifndef NO_GTK  ; this page is shown only when using gtk
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "gtk-gnutella - Gnutella servent"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecGtkPrivate} "GTK+ libraries, needed by gtk-gnutella. \
		This will install a private version of GTK+, usable only by gtk-gnutella."
	!insertmacro MUI_DESCRIPTION_TEXT ${SecGtkPublic} "GTK+ libraries, needed by gtk-gnutella. \
		This will install a system-wide version of GTK+, shareable with other programs."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
!endif


; ------------------ POST INSTALL


var gtk_dll_abs_path

Section -post
	SetShellVarContext all  ; use all user variables as opposed to current user

	; Don't set any paths for this exe if it has a private GTK+ installation.
!ifndef NO_GTK
	StrCmp $gtk_mode "private" skip_exe_PATH
!endif
	; set a special path for this exe, as GTK may not be in a global path.
	ReadRegStr $gtk_dll_abs_path HKLM "SOFTWARE\GTK\2.0" "DllPath"
	WriteRegStr HKLM "${REGISTRY_APP_PATHS}\gtk-gnutella.exe" "Path" "$gtk_dll_abs_path"
!ifndef NO_GTK
	skip_exe_PATH:
!endif

!ifndef NO_GTK
	WriteRegStr HKLM "SOFTWARE\${PRODUCT_NAME}" "GtkInstalledMode" "$gtk_mode"
!endif

	WriteRegStr HKLM "SOFTWARE\${PRODUCT_NAME}" "InstallationDirectory" "$INSTDIR"
	WriteRegStr HKLM "SOFTWARE\${PRODUCT_NAME}" "Vendor" "${PRODUCT_PUBLISHER}"

	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\gtk-gnutella_uninst.exe"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\icon.ico"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
	WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoModify" 1
	WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoRepair" 1

	; We don't need this, MUI takes care for us
	; WriteRegStr HKCU "Software\${PRODUCT_NAME}" "Installer Language" $sUAGE

	; write out uninstaller
	WriteUninstaller "$INSTDIR\gtk-gnutella_uninst.exe"

	; uninstall shortcut
	;CreateDirectory "$SMPROGRAMS\gtk-gnutella"
	;CreateShortCut "$SMPROGRAMS\gtk-gnutella\Uninstall gtk-gnutella.lnk" "$INSTDIR\gtk-gnutella_uninst.exe" "" ""

SectionEnd ; post





; ---------------- UNINSTALL



Function un.onUninstSuccess
	HideWindow
	MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer." /SD IDOK
FunctionEnd




Section Uninstall
	SetShellVarContext all  ; use all user variables as opposed to current user
	SetAutoClose false

!ifndef NO_GTK
	ReadRegStr $gtk_mode HKLM "SOFTWARE\${PRODUCT_NAME}" "GtkInstalledMode"
	StrCmp $gtk_mode "private" "" skip_gtk_remove
		; remove private GTK+, specify the same custom options are during installation
		ExecWait "$INSTDIR\gtk2_runtime_uninst.exe /remove_config=yes /sideeffects=no /dllpath=root /translations=no /compatdlls=no /S"
		; _?=$INSTDIR
		; Delete "$INSTDIR\gtk2_runtime_uninst.exe"  ; If using _? flag, it won't get deleted automatically, do it manually.
	skip_gtk_remove:
!endif

	; add delete commands to delete whatever files/registry keys/etc you installed here.
	Delete "$INSTDIR\gtk-gnutella_uninst.exe"

	DeleteRegKey HKLM "SOFTWARE\${PRODUCT_NAME}"
	DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"

	; gnutls
	Delete "$INSTDIR\libgnutls-26.dll"
	Delete "$INSTDIR\libgcrypt-11.dll"
	Delete "$INSTDIR\libgpg-error-0.dll"
	
	Delete "$INSTDIR\gtk-gnutella.exe"
	Delete "$INSTDIR\gtk-gnutella.nm"
	Delete "$INSTDIR\icon.ico"
	Delete "$INSTDIR\libiconv-2.dll"
	Delete "$INSTDIR\pthreadGC2.dll"
	Delete "$INSTDIR\pixmaps\*.xpm"
	Delete "$INSTDIR\pixmaps\*.png"
	Delete "$INSTDIR\extra_files\*.txt"
	
	RMDir /r "$INSTDIR\extra_files"
	RMDir /r "$INSTDIR\pixmaps"
	RMDir /r "$INSTDIR\share"	

	; clean up generated stuff
	Delete "$INSTDIR\*stdout.txt"
	Delete "$INSTDIR\*stderr.txt"

	RMDir "$INSTDIR"  ; only if empty

!ifndef NO_GTK
	StrCmp $gtk_mode "private" skip_exe_PATH_remove
!endif
	DeleteRegKey HKLM "${REGISTRY_APP_PATHS}\gtk-gnutella.exe"
!ifndef NO_GTK
	skip_exe_PATH_remove:
!endif

	Delete "$SMPROGRAMS\gtk-gnutella.lnk"
	;Delete "$SMPROGRAMS\gtk-gnutella\Uninstall gtk-gnutella.lnk"

SectionEnd ; end of uninstall section



; --------------- Helpers

; Detect previous installation
Function DetectPrevInstallation
	; if /removeold=no option is given, don't check anything.
	StrCmp $install_option_removeold "no" old_detect_done

	SetShellVarContext all  ; use all user variables as opposed to current user
	push $R0

	; detect previous installation
	ReadRegStr $R0 HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"
	StrCmp $R0 "" old_detect_done

	MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
		"${PRODUCT_NAME} is already installed. $\n$\nClick `OK` to remove the \
		previous version or `Cancel` to continue anyway." \
		/SD IDOK IDOK old_uninst
		; Abort
		goto old_detect_done

	; Run the old uninstaller
	old_uninst:
		ClearErrors
		IfSilent old_silent_uninst old_nosilent_uninst

		old_nosilent_uninst:
			ExecWait '$R0'
			goto old_uninst_continue

		old_silent_uninst:
			ExecWait '$R0 /S _?=$INSTDIR'

		old_uninst_continue:

		IfErrors old_no_remove_uninstaller

		; You can either use Delete /REBOOTOK in the uninstaller or add some code
		; here to remove to remove the uninstaller. Use a registry key to check
		; whether the user has chosen to uninstall. If you are using an uninstaller
		; components page, make sure all sections are uninstalled.
		old_no_remove_uninstaller:

	old_detect_done: ; old installation not found, all ok

	pop $R0
FunctionEnd



; detect GTK installation (any of available versions)
Function AskForGtk
	SetShellVarContext all  ; use all user variables as opposed to current user
	push $R0

	ReadRegStr $R0 HKLM "SOFTWARE\GTK\2.0" "DllPath"
	StrCmp $R0 "" no_gtk have_gtk

	no_gtk:
		MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
		"GTK2-Runtime is not installed. This product needs it to function properly.$\n\
		Please install GTK2-Runtime from http://gtk-win.sf.net/ first.$\n$\n\
		Click 'Cancel' to abort the installation \
		or 'OK' to continue anyway." \
		/SD IDOK IDOK have_gtk
		;Abort  ; Abort has different meaning from onpage callbacks, so use Quit
		Quit
		goto end_gtk_check

	have_gtk:
		; do nothing

	end_gtk_check:

	pop $R0
FunctionEnd



; Prevent running multiple instances of the installer
Function PreventMultipleInstances
	Push $R0
	System::Call 'kernel32::CreateMutexA(i 0, i 0, t ${PRODUCT_NAME}) ?e'
	Pop $R0
	StrCmp $R0 0 +3
		MessageBox MB_OK|MB_ICONEXCLAMATION "The installer is already running." /SD IDOK
		Abort
	Pop $R0
FunctionEnd

; eof
