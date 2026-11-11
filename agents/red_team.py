from dotenv import load_dotenv
from strands import Agent
from strands.models.anthropic import AnthropicModel
from strands.multiagent import Swarm

from agents.prompts import EXPLOIT_PROMPT, RECON_PROMPT
from agents.tools import send_http_request
from hooks import SandboxHook

load_dotenv()

MODEL_ID = "claude-haiku-5-5"
MAX_TOKENS = 4096


def build_model() -> AnthropicModel:
    """Build the shared Anthropic model."""
    return AnthropicModel(model_id=MODEL_ID, max_tokens=MAX_TOKENS)


def build_recon_agent(model: AnthropicModel) -> Agent:
    return Agent(
        name="recon",
        model=model,
        system_prompt=RECON_PROMPT,
        tools=[send_http_request],
    )


def build_exploit_agent(model: AnthropicModel) -> Agent:
    return Agent(
        name="exploit_crafter",
        model=model,
        system_prompt=EXPLOIT_PROMPT,
        tools=[send_http_request],
    )


def build_red_swarm() -> Swarm:
    """Build the Red Team swarm: Recon hands off to Exploit-Crafter, sandboxed to the local target."""
    model = build_model()
    recon = build_recon_agent(model)
    exploit = build_exploit_agent(model)
    return Swarm(
        nodes=[recon, exploit],
        entry_point=recon,
        hooks=[SandboxHook()],
        max_handoffs=6,
        max_iterations=20,
        execution_timeout=300.0,
        node_timeout=120.0,
    )
