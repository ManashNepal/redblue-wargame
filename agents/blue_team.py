from strands import Agent
from strands.models.anthropic import AnthropicModel
from strands.multiagent import Swarm

from agents.prompts import (
    DETECTOR_PROMPT,
    INCIDENT_WRITER_PROMPT,
    PATCHER_PROMPT,
)
from agents.red_team import build_model
from agents.tools import (
    edit_target_file,
    read_access_log,
    read_target_file,
    send_http_request,
)
from hooks import SandboxHook


def build_detector_agent(model: AnthropicModel) -> Agent:
    return Agent(
        name="detector",
        model=model,
        system_prompt=DETECTOR_PROMPT,
        tools=[read_access_log],
    )


def build_patcher_agent(model: AnthropicModel) -> Agent:
    return Agent(
        name="patcher",
        model=model,
        system_prompt=PATCHER_PROMPT,
        tools=[read_target_file, edit_target_file, send_http_request],
    )


def build_incident_writer_agent(model: AnthropicModel) -> Agent:
    return Agent(
        name="incident_writer",
        model=model,
        system_prompt=INCIDENT_WRITER_PROMPT,
        tools=[],
    )


def build_blue_swarm() -> Swarm:
    """Build the Blue Team swarm: Detector hands off to Patcher to Incident-Writer, sandboxed to the local target."""
    model = build_model()
    detector = build_detector_agent(model)
    patcher = build_patcher_agent(model)
    incident_writer = build_incident_writer_agent(model)
    return Swarm(
        nodes=[detector, patcher, incident_writer],
        entry_point=detector,
        hooks=[SandboxHook()],
        max_handoffs=8,
        max_iterations=30,
        execution_timeout=420.0,
        node_timeout=180.0,
    )
