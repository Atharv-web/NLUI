"""Small per-model failure backoff; never changes configured models."""
import asyncio
import time
from functools import wraps


def bounded_model_call(function):
    @wraps(function)
    async def call(self, **values):
        states = self.__dict__.setdefault('_model_failures', {})
        model = values['model']
        failures, retry_at = states.get(model, (0, 0))
        if time.monotonic() < retry_at:
            raise RuntimeError('Model temporarily unavailable; retry after 30 seconds.')
        try:
            result = await asyncio.wait_for(function(self, **values), timeout=60)
        except Exception:
            failures += 1
            states[model] = (failures, time.monotonic() + 30 if failures >= 3 else 0)
            raise
        states.pop(model, None)
        return result
    return call
