; Erik's AgentShield — NSIS installer hooks (included by the Tauri NSIS template).
;
; * Before installing over an existing copy: stop its daemon, which keeps agentshield.exe locked.
; * Before uninstalling: stop the daemon and remove exactly the Claude Code hooks and MCP proxy
;   wrappers that run THIS installation's agentshield.exe (other installations and other tools'
;   hooks are untouched; originals are restored exactly; backups are written first).
;   Skipped during an update (/UPDATE), so monitoring continues after upgrading.
; Hooks pointing to a removed binary would otherwise stay in ~/.claude/settings.json; with the
; optional fail-closed setting Claude Code would then block every tool call.

!macro NSIS_HOOK_PREINSTALL
  ${If} ${FileExists} "$INSTDIR\agentshield.exe"
    nsExec::Exec '"$INSTDIR\agentshield.exe" daemon stop'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} ${FileExists} "$INSTDIR\agentshield.exe"
    nsExec::Exec '"$INSTDIR\agentshield.exe" daemon stop'
    Pop $0
    ${If} $UpdateMode <> 1
      nsExec::Exec '"$INSTDIR\agentshield.exe" agent uninstall claude-code --yes --only-this-binary'
      Pop $0
      nsExec::Exec '"$INSTDIR\agentshield.exe" mcp unwrap --yes --only-this-binary'
      Pop $0
    ${EndIf}
  ${EndIf}
!macroend
