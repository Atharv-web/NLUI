"""Approved local commands. A working directory is NOT a security sandbox.

The caller must obtain approval before run(); this module never grants authority.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess


class LocalExecutionError(RuntimeError):
    pass


def _command(workspace, argv):
    root = Path(workspace).expanduser().resolve(strict=True)
    if not root.is_dir() or not isinstance(argv, list) or not argv or len(argv) > 128:
        raise LocalExecutionError("invalid_workspace_or_command")
    if any(not isinstance(arg, str) or "\0" in arg or len(arg) > 32768 for arg in argv):
        raise LocalExecutionError("invalid_command_argument")
    first = Path(argv[0])
    executable = str((root / first).resolve(strict=True)) if first.is_absolute() or first.parent != Path('.') else shutil.which(argv[0])
    if not executable or not Path(executable).is_file():
        raise LocalExecutionError("command_not_found")
    # Windows implicitly invokes cmd.exe for batch files. Require the user to
    # approve an explicit interpreter command instead of silently doing so.
    if Path(executable).suffix.lower() in {'.bat', '.cmd'}:
        raise LocalExecutionError("batch_file_requires_explicit_interpreter")
    return root, [str(Path(executable).resolve(strict=True)), *argv[1:]]


class CommandApprovalScopes:
    """In-memory exact-command grants, never transferable across tasks.

    Source edits invalidate reuse. Dependencies and VCS data are excluded from
    the bounded source fingerprint; this is approval scoping, not containment.
    """
    def __init__(self):
        self._grants = set()

    def _key(self, task_id, workspace, argv):
        if not isinstance(task_id, str) or not task_id:
            raise LocalExecutionError("task_id_required")
        root, command = _command(workspace, argv)
        digest = hashlib.sha256()
        excluded = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache'}
        count = size = 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            if any((Path(directory) / item).is_symlink() or
                   (hasattr(Path(directory) / item, 'is_junction') and (Path(directory) / item).is_junction())
                   for item in dirs):
                raise LocalExecutionError("scope_contains_linked_directory")
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink():
                    raise LocalExecutionError("scope_contains_symlink")
                count += 1
                size += path.stat().st_size
                if count > 10000 or size > 64 * 1024 * 1024:
                    raise LocalExecutionError("workspace_too_large_for_reusable_approval")
                digest.update(str(path.relative_to(root)).encode())
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        # Bind interpreter contents as well as explicit script arguments,
        # including scripts outside the selected workspace.
        for arg in command:
            path = Path(arg)
            candidate = path if path.is_absolute() else root / path
            try:
                if candidate.is_file():
                    with candidate.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk)
            except (OSError, ValueError):
                raise LocalExecutionError("cannot_bind_command_file") from None
        return task_id, os.path.normcase(str(root)), json.dumps(command), digest.hexdigest()

    def grant(self, task_id, workspace, argv):
        self._grants.add(self._key(task_id, workspace, argv))

    def matches(self, task_id, workspace, argv):
        try:
            return self._key(task_id, workspace, argv) in self._grants
        except (OSError, ValueError, LocalExecutionError):
            return False

    def revoke(self, task_id):
        self._grants = {key for key in self._grants if key[0] != task_id}


class LocalCommandRunner:
    OUTPUT_LIMIT = 65536

    async def _stop(self, process):
        if process.returncode is not None:
            return
        if os.name == 'nt':
            killer = await asyncio.create_subprocess_exec(
                str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'taskkill.exe'),
                '/PID', str(process.pid), '/T', '/F',
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                await asyncio.wait_for(killer.wait(), 5)
            except TimeoutError:
                killer.kill()
                await killer.wait()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()

    async def run(self, workspace, argv, purpose='test', timeout_seconds=60):
        if not isinstance(purpose, str) or purpose not in {'test', 'run', 'build', 'install', 'launch'}:
            raise LocalExecutionError("invalid_command_purpose")
        if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 600:
            raise LocalExecutionError("invalid_command_timeout")
        root, command = _command(workspace, argv)
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        try:
            process = await asyncio.create_subprocess_exec(
                *command, cwd=str(root), stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, **options)
        except OSError:
            raise LocalExecutionError("command_launch_failed") from None
        output = bytearray()
        truncated = False
        timed_out = False
        async def collect():
            nonlocal truncated
            while chunk := await process.stdout.read(4096):
                remaining = self.OUTPUT_LIMIT - len(output)
                output.extend(chunk[:remaining])
                truncated |= len(chunk) > remaining
            await process.wait()
        try:
            await asyncio.wait_for(collect(), timeout_seconds)
        except TimeoutError:
            timed_out = True
            await self._stop(process)
        except asyncio.CancelledError:
            await self._stop(process)
            raise
        finally:
            if process.returncode is None:
                await self._stop(process)
        return {'exit_code': process.returncode, 'output': output.decode('utf-8', errors='replace'),
                'output_sha256': hashlib.sha256(output).hexdigest(),
                'timed_out': timed_out, 'output_truncated': truncated,
                'workspace': str(root), 'argv': command, 'purpose': purpose}
