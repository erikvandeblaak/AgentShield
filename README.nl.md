<p align="center"><img src="apps/desktop/brand/logo-dark-bg.svg" alt="Erik&#39;s AgentShield" width="360"></p>

<h3 align="center">Lokale beveiliging &amp; observability voor AI-agents</h3>
<p align="center"><b>Your AI. Your machine. Your rules.</b></p>

**Erik's AgentShield** laat zien wat je AI-codingagent (Claude Code) werkelijk op je machine doet — elk
shellcommando, elke bestandstoegang, web-fetch en MCP-aanroep — beoordeelt het risico met een
uitlegbare engine en dwingt, als jij dat kiest, je policy af *voordat* de actie draait. Alles blijft
lokaal: geen account, geen cloud, geen telemetrie.

## De vijf modi

| Modus | Blokkeert? | Wat er gebeurt |
|---|---|---|
| **Monitor** (standaard) | nooit | Registreert en scoort alles. |
| **Shadow** | nooit | Registreert wat de policy *zou* doen (zou weigeren / zou vragen). |
| **Interactive** | via Claude Code | Risicovolle acties gaan naar de eigen goedkeuringsprompt van Claude Code; harde regels weigeren. |
| **Enforce** | ja | Policy `deny` → geblokkeerd vóór uitvoering; `ask` → native prompt. |
| **Lockdown** | ja | Elke muterende, netwerk- of risicovolle actie wordt geweigerd tot je terugschakelt. |

AgentShield geeft **nooit** `allow` terug en herschrijft nooit toolinput: het kan Claude Code alleen
strenger maken, nooit zwakker dan de eigen permissie-instellingen.

## Eerlijke dekking

AgentShield ziet wat de hooks van Claude Code tonen. Het ziet niet wat child-processen doen buiten hun
commandline, vangt geen netwerkverkeer af en sandboxt niet. De
[capability matrix](docs/AGENT_CAPABILITY_MATRIX.md) toont precies wat afgedwongen, geobserveerd,
gedeeltelijk of niet ondersteund wordt — ook in de app. Andere agents worden gedetecteerd maar **niet gemonitord**.

## Installeren & eerste start

```powershell
cargo build --release -p agentshield
target\release\agentshield.exe agent install claude-code --dry-run   # toont exact wat er verandert
target\release\agentshield.exe agent install claude-code              # vraagt bevestiging, maakt eerst een backup
target\release\agentshield.exe selftest                               # echte hook → engine → auditlog
```

De installer voegt AgentShield-hooks toe aan `~/.claude/settings.json` (exec-vorm, zonder shell), behoudt
alle bestaande hooks en permissies, maakt eerst een backup en verifieert het resultaat.
`agentshield agent uninstall claude-code` verwijdert alleen de AgentShield-regels.

## Ontwikkelen

Open `AgentShield.code-workspace` (of de map) in VS Code: aanbevolen extensies, rust-analyzer voor beide
Cargo-workspaces, tasks (`Kwaliteitspoort`, `Linux-validatie`, hook-fixtures, desktop dev) en
debugconfiguraties — allemaal met een geïsoleerd testprofiel in `target/dev`. Zie [CLAUDE.md](CLAUDE.md).

Licentie: Apache-2.0. Ontwikkeld door **Erik van de Blaak** — [vandeblaak.com](https://www.vandeblaak.com).
