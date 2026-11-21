# RedBlue Wargame

A multi-agent security wargame built with the [Strands Agents SDK](https://strandsagents.com).
A **Red Team** of AI agents attacks a deliberately vulnerable web app, and a **Blue Team** of AI agents detects and patches the flaws. They loop until every vulnerability is fixed.

## How it works

```
Red attacks  ->  Blue patches  ->  Score  ->  all fixed? stop : loop again
```

| Team | Agents | Job |
|------|--------|-----|
| Red  | Recon, Exploit | Find weaknesses, then prove each one with a real request |
| Blue | Detector, Patcher, Incident-Writer | Spot attacks in the access log, fix the code, write a report |

After each round, a **deterministic scorer** re-runs every attack over HTTP to check what is really fixed. Agents never score themselves.

## The target app

A small FastAPI + SQLite app with four planted vulnerabilities:

| Vulnerability | Where | Problem |
|---------------|-------|---------|
| Admin bypass | `/admin` | No authentication |
| SQL injection | `/search` | User input pasted into raw SQL |
| Session hijack | `/account` | Guessable tokens like `session-1` |
| Timing attack | `/login` | Faster response for unknown usernames |

## Safety

- **Sandbox hook**: blocks any agent request that isn't aimed at the local target.
- **Compile guard**: rejects any code edit that would break the app.

## Setup

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and an Anthropic API key.

```bash
uv sync
echo "ANTHROPIC_API_KEY=your-key" > .env
```

## Run

**1. Start the target app** (keep this terminal open):

```bash
uv run uvicorn target_app.app:app --reload --port 8001
```

**2. Play a match** (in a second terminal):

```bash
uv run python main.py
```

Options: `--rounds` (default 3), `--timeout` in seconds (default 300).

To reset the app to its vulnerable state after a match:

```bash
git checkout target_app/app.py
```

## Evaluation

```bash
uv run python -m eval.run_eval --mode deterministic --runs 3
uv run python -m eval.run_eval --mode behavioral
uv run python -m eval.run_eval --mode both
```

- **Deterministic**: plays several matches and reports how often each vulnerability gets patched.
- **Behavioral**: an LLM judge grades the Blue Team's incident report for honesty and usefulness, checked against the real patch results.

## Project structure

```
target_app/        vulnerable FastAPI app
agents/            Red and Blue agents, tools, prompts
hooks.py           sandbox hook
game_controller.py match loop and scorer
main.py            CLI
eval/              deterministic and behavioral evals
```

## Tech stack

Python, Strands Agents SDK, Strands Evals, Anthropic API, FastAPI, SQLAlchemy, httpx, Rich, Click
