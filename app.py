"""FastAPI app for the VulnReach PR conversation agent.

Endpoints:
* GET    /verdicts   — list stored verdicts (id, package, version, status)
* POST   /chat       — {verdict_id, message} -> agent reply
* GET    /           — minimal single-page HTML chat UI

Verdicts are stored in memory (a dict keyed by verdict_id).  Each stored entry
keeps the full analysis context so the agent can re-run the analyzer when a user
challenges a verdict or supplies new information.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from vulnreach.agent.pr_chat import PRChatAgent, RuleBasedLLMClient, build_pr_comment

app = FastAPI(title="VulnReach PR Chat", version="0.1.0")

# In-memory store: verdict_id -> analysis context.
# In production this would be backed by a database.
_VERDICTS: dict[str, dict[str, Any]] = {}


class ChatRequest(BaseModel):
    verdict_id: str
    message: str


class VerdictSummary(BaseModel):
    verdict_id: str
    package: str
    version: str
    advisory_id: str
    status: str
    confidence: str


def _register_verdict(
    *,
    verdict_id: str,
    verdict: Any,
    analyzer: Any,
    project_path: str,
    alert: Any,
    vulnerable_functions: list[Any],
    fix_commit: Any,
    call_graph: Any,
) -> None:
    _VERDICTS[verdict_id] = {
        "verdict": verdict,
        "analyzer": analyzer,
        "project_path": project_path,
        "alert": alert,
        "vulnerable_functions": vulnerable_functions,
        "fix_commit": fix_commit,
        "call_graph": call_graph,
    }


@app.get("/verdicts", response_model=list[VerdictSummary])
def list_verdicts() -> list[VerdictSummary]:
    """List all stored verdicts."""
    return [
        VerdictSummary(
            verdict_id=vid,
            package=entry["alert"].package,
            version=entry["alert"].version,
            advisory_id=entry["alert"].advisory_id,
            status=entry["verdict"].status,
            confidence=entry["verdict"].confidence,
        )
        for vid, entry in _VERDICTS.items()
    ]


@app.post("/chat")
def chat(req: ChatRequest) -> JSONResponse:
    """Reply to a user message about a verdict."""
    entry = _VERDICTS.get(req.verdict_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"verdict {req.verdict_id} not found")

    agent = PRChatAgent(
        verdict=entry["verdict"],
        analyzer=entry["analyzer"],
        project_path=entry["project_path"],
        alert=entry["alert"],
        vulnerable_functions=entry["vulnerable_functions"],
        fix_commit=entry["fix_commit"],
        call_graph=entry["call_graph"],
        # No LLM endpoint required: the built-in RuleBasedLLMClient is used.
    )

    reply = agent.respond(req.message)
    # Persist any updated verdict.
    entry["verdict"] = agent.verdict
    return JSONResponse({"reply": reply, "verdict": agent.verdict.model_dump()})


@app.get("/", response_class=HTMLResponse)
def chat_ui() -> str:
    """Minimal single-page HTML chat UI."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnReach PR Chat</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto;
         padding: 0 1rem; line-height: 1.5; color: #222; }
  header { border-bottom: 2px solid #e5e7eb; padding-bottom: 1rem; margin-bottom: 1rem; }
  .verdict-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 1rem;
                   font-weight: 600; font-size: 0.875rem; }
  .reachable { background: #fecaca; color: #991b1b; }
  .not_reachable { background: #d1fae5; color: #065f46; }
  .uncertain { background: #fef3c7; color: #92400e; }
  #messages { border: 1px solid #e5e7eb; border-radius: 0.5rem; height: 400px;
              overflow-y: auto; padding: 1rem; margin-bottom: 1rem;
              background: #f9fafb; }
  .msg { margin-bottom: 1rem; padding: 0.75rem; border-radius: 0.5rem; }
  .user { background: #e5edff; margin-left: 2rem; }
  .assistant { background: #ffffff; border: 1px solid #e5e7eb; }
  pre { background: #f3f4f6; padding: 0.5rem; border-radius: 0.375rem;
        font-size: 0.875rem; overflow-x: auto; }
  form { display: flex; gap: 0.5rem; }
  input[type="text"] { flex: 1; padding: 0.5rem; border: 1px solid #d1d5db;
                       border-radius: 0.375rem; font-size: 1rem; }
  button { padding: 0.5rem 1rem; background: #2563eb; color: white;
           border: none; border-radius: 0.375rem; cursor: pointer; font-size: 1rem; }
  button:hover { background: #1d4ed8; }
  .hint { color: #6b7280; font-size: 0.875rem; margin-top: 0.5rem; }
</style>
</head>
<body>
<header>
  <h1>VulnReach PR Chat</h1>
  <p class="hint">Ask about a vulnerability verdict. The agent answers only from
     the analysis report evidence.</p>
</header>

<div id="verdicts"></div>

<div id="messages">
  <div class="msg assistant">
    Hi! I'm the VulnReach PR chat agent. Select a verdict above, then ask me
    about it. I only answer from evidence in the report — I quote file:line
    hops and never claim certainty I don't have.
  </div>
</div>

<form id="chat-form">
  <input type="text" id="message" placeholder="Ask about the verdict..." required>
  <button type="submit">Send</button>
</form>

<script>
const verdictsEl = document.getElementById('verdicts');
const messagesEl = document.getElementById('messages');
const form = document.getElementById('chat-form');
const messageInput = document.getElementById('message');

let currentVerdictId = null;

async function loadVerdicts() {
  const res = await fetch('/verdicts');
  const list = await res.json();
  verdictsEl.innerHTML = '<h3>Verdicts</h3>' +
    list.map(v => `
      <div style="margin-bottom: 0.5rem;">
        <span class="verdict-badge ${v.status}">${v.status}</span>
        <b>${v.package}@${v.version}</b> — ${v.advisory_id}
        <button onclick="selectVerdict('${v.verdict_id}', '${v.package}@${v.version}')" style="margin-left:0.5rem;">Open</button>
      </div>
    `).join('');
}

async function selectVerdict(id, label) {
  currentVerdictId = id;
  messagesEl.innerHTML = `
    <div class="msg assistant">
      <b>Discussing ${label}</b><br>
      Ask me anything about this verdict. I only answer from the report evidence.
    </div>`;
  messageInput.focus();
}

function addMessage(text, role) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !currentVerdictId) return;
  addMessage(text, 'user');
  messageInput.value = '';
  try {
    const res = await fetch('/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({verdict_id: currentVerdictId, message: text}),
    });
    const data = await res.json();
    addMessage(data.reply, 'assistant');
  } catch (err) {
    addMessage('Error: ' + err, 'assistant');
  }
});

loadVerdicts();
</script>
</body>
</html>
"""


def seed_demo_verdicts() -> None:
    """Seed the store with the demo scenario verdicts (called on import)."""
    # This is intentionally a no-op here; the demo script populates the store.
    pass
