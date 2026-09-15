"""Private legacy diagnostic routing. Dynamic work content never enters logs."""
import sys

_logger = None


def install_logger(logger):
    global _logger
    _logger = logger


def diagnostic(*args, **kwargs):
    # Legacy strings mix prompts, transcripts, credentials and exceptions.
    # Preserve where the event happened, never guess which fragments are safe.
    logger = _logger
    if logger is not None:
        caller = sys._getframe(1)
        logger.log("debug", caller.f_globals.get("__name__", "legacy"),
                   "legacy_diagnostic", "Legacy diagnostic emitted.",
                   result={"line": caller.f_lineno})
