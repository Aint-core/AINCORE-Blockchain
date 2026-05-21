# AINCORE Crew — Native Claude Code Multi-Agent System

Panggil gue (orchestrator) dengan format:
  `/crew <department> <task>`

Atau langsung bilang:
  "jalanin security audit"
  "bikin sprint plan buat phase 3"
  "research VDF implementation"
  "pentest RPC layer"

---

## Departments & Triggers

| Department | Trigger kata | Agent yang di-spawn |
|---|---|---|
| PM | "sprint", "roadmap", "planning", "prioritas" | PM Agent |
| Security | "security audit", "vulnerability", "threat" | Security Lead + Threat Modeler |
| Audit | "code audit", "review kode", "audit" | Code Auditor |
| Pentest | "pentest", "red team", "exploit" | Pen Tester |
| Dev | "implement", "fix bug", "code ini" | Blockchain Dev |
| QA | "test", "coverage", "validasi" | QA Lead |
| Research | "research", "riset", "compare" | Researcher + Tech Writer |
| Full Sprint | "full sprint", "jalanin semua" | All departments sequential |

---

## Agent Roles (loaded by orchestrator)

Defined in: `.claude/crew/agents/*.md`
