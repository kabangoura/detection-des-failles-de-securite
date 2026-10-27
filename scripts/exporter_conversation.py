"""Exporte une conversation Claude Code (fichier .jsonl) en Markdown lisible.

Usage : python scripts/exporter_conversation.py CHEMIN.jsonl SORTIE.md

- Les messages de l'étudiant et de l'IA sont conservés intégralement, dans l'ordre d'origine.
- Les questions à choix posées par l'IA et les réponses de l'étudiant sont incluses (ce sont des décisions).
- Les captures d'écran jointes par l'étudiant sont signalées.
- Les actions de l'IA (lecture de fichiers, commandes, écriture de code) sont résumées en une ligne
  pour garder le document lisible ; le code produit se trouve dans le projet lui-même.
- Les rappels techniques injectés par l'outil (balises <system-reminder>) sont retirés.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
_PASTED = re.compile(r"</?pasted_content[^>]*>")
# Clés secrètes (PyPI, xAI/Grok, GitHub, Cloudflare) : jamais dans le document remis
_SECRET = re.compile(r"\b(pypi-[A-Za-z0-9_\-]{16,}|xai-[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
_SUMMARY = "This session is being continued from a previous conversation"


def _clean(text: str) -> str:
    return _SECRET.sub("[CLÉ MASQUÉE]", _PASTED.sub("", _REMINDER.sub("", text))).strip()


def _action(block: dict) -> str:
    name = block.get("name", "outil")
    inp = block.get("input") or {}
    if name in ("Write", "Edit", "Read"):
        path = Path(str(inp.get("file_path", ""))).name
        verb = {"Write": "Écriture du fichier", "Edit": "Modification du fichier", "Read": "Lecture du fichier"}[name]
        return f"{verb} `{path}`"
    if name in ("Bash", "PowerShell"):
        return f"Commande : {_clean(inp.get('description') or str(inp.get('command', ''))[:80])}"
    if name in ("WebFetch", "WebSearch"):
        return f"Recherche web : {inp.get('url') or inp.get('query')}"
    return f"Outil {name}"


def _questions(block: dict) -> list[str]:
    lines = []
    for q in (block.get("input") or {}).get("questions", []):
        options = " / ".join(o.get("label", "") for o in q.get("options", []))
        lines.append(f"**Question :** {q.get('question')}  \n*Choix proposés :* {options}")
    return lines


def _result_text(block: dict) -> str:
    content = block.get("content")
    if isinstance(content, list):
        return " ".join(c.get("text", "") for c in content if isinstance(c, dict))
    return str(content or "")


def export(src: Path, dst: Path) -> int:
    lines = ["# Conversation complète - KMB Library", "",
             "Outil : Claude Code (extension VS Code), modèle Claude Opus.",
             "Fichiers fournis à l'IA au départ : énoncé du projet, consignes des livrables 1 et 2, "
             "`projet.txt` (cahier des charges CyberAudit AI rédigé par l'étudiant).",
             "Les actions techniques de l'IA sont résumées entre crochets ; le code complet est dans le projet.",
             "Les questions à choix de l'IA et les réponses de l'étudiant sont reproduites telles quelles.", ""]
    count = 0
    pending_actions: list[str] = []
    asked: set[str] = set()  # identifiants des questionnaires (AskUserQuestion)

    def flush():
        if pending_actions:
            lines.append("> " + "  \n> ".join(f"[{a}]" for a in pending_actions))
            lines.append("")
            pending_actions.clear()

    for raw in src.read_text(encoding="utf-8").splitlines():
        d = json.loads(raw)
        kind = d.get("type")
        if kind not in ("user", "assistant") or d.get("isMeta"):
            continue
        content = d["message"]["content"]
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
        images = sum(1 for b in blocks if b.get("type") == "image")
        for b in blocks:
            t = b.get("type")
            if t == "text":
                text = _clean(b["text"])
                if not text or text.startswith("<command-") or text == "Tool loaded." or text.startswith("[Image: source:"):
                    continue
                flush()
                if text.startswith(_SUMMARY):
                    # Résumé inséré par l'outil quand la conversation devient trop longue : ce n'est pas l'étudiant
                    lines += ["### Reprise de contexte (résumé automatique de l'outil)", "",
                              "*La conversation dépassait la mémoire de travail de l'IA : l'outil a résumé la partie "
                              "précédente pour continuer. Le résumé est reproduit ci-dessous.*", "", text, ""]
                    continue
                who = "Étudiant" if kind == "user" else "IA (Claude)"
                if kind == "user" and images:
                    text += f"\n\n*({images} capture(s) d'écran jointe(s))*"
                    images = 0
                lines += [f"### {who}", "", text, ""]
                count += 1
            elif t == "tool_use" and b.get("name") == "AskUserQuestion":
                flush()
                asked.add(b.get("id"))
                lines += ["### IA (Claude) - questionnaire", "", *_questions(b), ""]
                count += 1
            elif t == "tool_use":
                pending_actions.append(_action(b))
            elif t == "tool_result" and b.get("tool_use_id") in asked:
                flush()
                answer = _clean(_result_text(b)).replace("Your questions have been answered:", "").split("You can now continue")[0].strip()
                lines += ["### Étudiant - réponses au questionnaire", "", answer, ""]
                count += 1
        if kind == "user" and images:  # capture seule, sans texte
            flush()
            lines += ["### Étudiant", "", f"*({images} capture(s) d'écran jointe(s))*", ""]
    flush()
    dst.write_text("\n".join(lines), encoding="utf-8")
    return count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    n = export(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"{n} messages exportés vers {sys.argv[2]}")
