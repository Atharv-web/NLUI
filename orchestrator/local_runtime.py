"""Local application lifecycle; SQLite is the sole durable authority."""
from __future__ import annotations

import asyncio
from pathlib import Path

from .config import OrchestratorConfig
from .persistence import DurableStore, create_durable_store
from .persistence.secrets import SecretStore


class LocalRuntime:
    """Own startup integrity verification and graceful SQLite checkpointing."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store
        self.started = False
        self.closed = False

    async def start(self) -> None:
        if self.closed:
            raise RuntimeError("local runtime is closed")
        if self.started:
            return
        # Disk work must not block the voice event loop.
        await asyncio.to_thread(self.store.initialize, verify_integrity=True)
        self.started = True

    async def stop(self) -> None:
        if self.closed:
            return
        if self.started:
            await asyncio.to_thread(self.store.database.checkpoint, "PASSIVE")
        self.closed = True
        self.started = False


def create_local_runtime(
    base_dir: Path,
    config: OrchestratorConfig,
    *,
    secret_store: SecretStore | None = None,
) -> LocalRuntime:
    return LocalRuntime(create_durable_store(
        base_dir, config, secret_store=secret_store, initialize=False
    ))
