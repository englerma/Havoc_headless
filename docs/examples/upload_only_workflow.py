"""Minimal workflow that uploads a single file to a remote agent."""

from __future__ import annotations

from typing import List

from headless_workflow import (
    WorkflowConfig,
    WorkflowStep,
    encode_path,
    make_task,
    read_file_b64,
)


def build_upload_workflow(cfg: WorkflowConfig, agent_id: str) -> List[WorkflowStep]:
    """Return a workflow that only uploads the configured executable."""

    steps: List[WorkflowStep] = []

    def append(step: WorkflowStep, *, name: str) -> None:
        step.name = name
        steps.append(step)

    append(
        make_task(
            cfg.username,
            agent_id,
            15,
            f"upload {cfg.local_exe} {cfg.remote_exe}",
            SubCommand="upload",
            Arguments=encode_path(cfg.remote_exe),
            File=read_file_b64(cfg.local_exe),
        ),
        name="upload_summon",
    )

    return steps


__all__ = ["build_upload_workflow"]
