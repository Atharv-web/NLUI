import platform as _platform
import subprocess as _subprocess

# ── Nuclear: force CREATE_NO_WINDOW on EVERY subprocess call on Windows ───────
# This patches Popen itself, so no per-file flag is needed anywhere.
if _platform.system() == "Windows":
    _OrigPopen = _subprocess.Popen

    class _Popen(_OrigPopen):
        def __init__(self, args, **kw):
            kw["creationflags"] = kw.get("creationflags", 0) | _subprocess.CREATE_NO_WINDOW
            kw.pop("startupinfo", None)   # drop any stale/shared STARTUPINFO
            super().__init__(args, **kw)

    _subprocess.Popen = _Popen
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import threading
import time
import json
import sys
import traceback
from datetime import datetime
from pathlib import Path

import sounddevice as sd
from google import genai
from google.genai import types
from ui import JarvisUI
from core.logging_service import JarvisLogger
from orchestrator.model_capabilities import (
    CapabilityStatus,
    GoogleModelMetadataProvider,
    check_model_capabilities,
)
from orchestrator.runtime_models import RUNTIME_ORCHESTRATOR_CONFIG, VOICE_MODEL
from orchestrator.coordination import (
    CoordinationHealth,
    CoordinationLifecycle,
    CoordinationMode,
    create_application_coordination,
)
from orchestrator.safety import (
    CallableToolAdapter,
    ExecutionGateway,
    GatewayDisposition,
    LegacyToolIntake,
    ToolAdapterRegistry,
)
from core.live_audio import (
    drain_async_queue as _drain_async_queue,
    merge_transcript as _merge_transcript,
    put_latest as _put_latest,
)
from memory.memory_manager import (
    load_memory, update_memory, format_memory_for_prompt,
    save_session_summary, pop_last_session,
)

from actions.file_processor import file_processor
from actions.flight_finder     import flight_finder
from actions.open_app          import open_app
from actions.weather_report    import weather_action
from actions.send_message      import send_message
from actions.reminder          import reminder
from actions.computer_settings import computer_settings
from actions.screen_processor  import _capture_camera, _capture_screen
from actions.youtube_video     import youtube_video
from actions.desktop           import desktop_control
from actions.browser_control   import browser_control
from actions.file_controller   import file_controller
from actions.code_helper       import code_helper
from actions.dev_agent         import dev_agent
from actions.web_search        import web_search as web_search_action
from actions.computer_control  import computer_control
from actions.game_updater      import game_updater
from actions.system_monitor    import SystemMonitor, get_system_status
from actions.proactive         import ProactiveEngine
from actions.background_monitor import (
    add_monitor, remove_monitor, list_monitors, check_all as monitor_check_all,
)
from actions.web_search        import _news as _fetch_news_sync
from memory.config_manager     import get_brief_enabled


def get_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


BASE_DIR        = get_base_dir()
API_CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"
PROMPT_PATH     = BASE_DIR / "core" / "prompt.txt"
ORCHESTRATOR_CONFIG = RUNTIME_ORCHESTRATOR_CONFIG
LIVE_MODEL          = VOICE_MODEL
CHANNELS            = 1
SEND_SAMPLE_RATE    = 16000
RECEIVE_SAMPLE_RATE = 24000
INPUT_CHUNK_FRAMES  = 640   # 40 ms at 16 kHz: low latency without packet spam
INPUT_QUEUE_MAX     = 25    # 1 second; stale mic audio is worse than dropped audio
PLAYBACK_QUEUE_MAX  = 100   # 2 seconds of 20 ms output slices
PLAYBACK_SLICE_BYTES = 960  # 20 ms at 24 kHz, mono int16
PLAYBACK_BATCH_BYTES = 3840 # max 80 ms per blocking device write
INPUT_AUDIO_MIME    = f"audio/pcm;rate={SEND_SAMPLE_RATE}"


def _get_api_key() -> str:
    with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["gemini_api_key"]


def _load_system_prompt() -> str:
    try:
        return PROMPT_PATH.read_text(encoding="utf-8")
    except Exception:
        return (
            "You are JARVIS, My AI assistant. "
            "Be concise, direct, and always use the provided tools to complete tasks. "
            "Never simulate or guess results — always call the appropriate tool."
        )

from orchestrator.tool_declarations import TOOL_DECLARATIONS

# --- Plugin system ---


class JarvisLive:

    def __init__(self, ui: JarvisUI):
        self.ui             = ui
        self.logger         = JarvisLogger(BASE_DIR)
        self._active_trace_id: str | None = None
        self._model_capabilities_checked = False
        self._coordination: CoordinationLifecycle | None = None
        self._execution_gateway: ExecutionGateway | None = None
        self._tool_intake: LegacyToolIntake | None = None
        self._asst_name     = "JARVIS"   # updated each session from config
        self.session              = None
        self.audio_in_queue       = None
        self.out_queue            = None
        self._loop                = None
        self._send_lock: asyncio.Lock | None = None
        self._resumption_handle: str | None = None
        self._is_speaking         = False
        self._speaking_lock       = threading.Lock()
        self._barge_in_enabled     = False   # opt-in on PC speakers; avoids self-echo
        self._phone_barge_in_enabled = True # browser mic has acoustic echo cancellation
        self._audio_stream_ended   = False
        self._phone_active        = False   # True while phone mic is streaming; pauses PC mic
        self._pending_vision       = None    # (img_bytes, mime_type, question, angle) to inject after tool response
        self._vision_cam_active    = False   # True if camera was opened for vision → auto-close after response
        self._vision_close_pending = False   # True after vision injected; next turn_complete closes camera
        self._vision_last_time     = 0.0     # monotonic time of last screen_process call (cooldown guard)
        self._vision_busy          = False   # True while a vision capture/inject cycle is in flight
        self._interrupted          = False   # True while draining audio after user interrupt
        self.ui.on_text_command   = self._on_text_command
        self.ui.on_remote_clicked = self._make_remote_key
        self.ui.on_interrupt      = self.interrupt
        self.ui.on_barge_in_changed = self._set_barge_in
        self.ui.on_open_debug_logs = self.logger.get_events
        self.ui.on_debug_log_sources = self.logger.get_sources
        self._turn_done_event: asyncio.Event | None = None
        self._dashboard     = None
        self._briefing_sent    = False          # morning briefing fires once per process
        self._sys_monitor      = SystemMonitor()  # persistent cooldown state
        self._proactive        = ProactiveEngine()
        self._last_user_speech = time.monotonic()  # updated on every user utterance
        self._session_log: list[str] = []          # conversation turns for end-of-session summary

    def _make_remote_key(self):
        """Called from Qt main thread when user presses Remote Control."""
        if self._dashboard is None:
            self.ui.write_log(
                "SYS: Dashboard unavailable. "
                "Run: pip install fastapi \"uvicorn[standard]\" cryptography"
            )
            return None
        key    = self._dashboard.new_key()
        url    = self._dashboard.get_url()
        manual = self._dashboard.get_manual_url()
        return url, key, f"{url}/auto-login?key={key}", manual

    def _on_text_command(self, text: str):
        if not self._loop or not self.session:
            return
        self._active_trace_id = self.logger.new_trace_id()
        self.logger.log(
            "info", "voice", "user_input", "Text command received.",
            trace_id=self._active_trace_id, arguments={"text": text},
        )
        asyncio.run_coroutine_threadsafe(self._send_text(text), self._loop)

    async def _send_text(self, text: str) -> None:
        """Send conversational text through the low-latency realtime channel."""
        if not text or not self.session:
            return
        lock = self._send_lock
        if lock is None:
            return
        async with lock:
            await self.session.send_realtime_input(text=text)

    async def _send_video_prompt(
        self, image: bytes, mime_type: str, prompt: str
    ) -> None:
        """Keep a vision frame and its prompt adjacent on the websocket."""
        if not self.session or not self._send_lock:
            return
        async with self._send_lock:
            await self.session.send_realtime_input(
                video=types.Blob(data=image, mime_type=mime_type)
            )
            await self.session.send_realtime_input(text=prompt)

    async def _send_audio_stream_end(self) -> None:
        """Flush Gemini's cached input whenever microphone streaming pauses."""
        if not self.session or not self._send_lock or self._audio_stream_ended:
            return
        async with self._send_lock:
            await self.session.send_realtime_input(audio_stream_end=True)
        self._audio_stream_ended = True

    def set_speaking(self, value: bool):
        with self._speaking_lock:
            self._is_speaking = value
        if value:
            self.ui.set_state("SPEAKING")
        elif not self.ui.muted:
            self.ui.set_state("LISTENING")

    def _set_barge_in(self, enabled: bool) -> None:
        self._barge_in_enabled = bool(enabled)

    def interrupt(self) -> None:
        """Stop JARVIS mid-speech: drain queued audio and open mic immediately."""
        self._interrupted = True
        if self._loop:
            self._loop.call_soon_threadsafe(self._finish_manual_interrupt)
        else:
            self._finish_manual_interrupt()

    def _finish_manual_interrupt(self) -> None:
        """Complete interruption on the asyncio thread; asyncio.Queue is not thread-safe."""
        drained = _drain_async_queue(self.audio_in_queue)
        if drained:
            print(f"[JARVIS] ✋ Interrupted — {drained} audio chunks discarded")
        self.set_speaking(False)
        if self._turn_done_event:
            self._turn_done_event.clear()
        self.ui.write_log("SYS: Interrupted — listening...")

    def speak(self, text: str):
        if not self._loop or not self.session:
            return
        asyncio.run_coroutine_threadsafe(self._send_text(text), self._loop)

    def speak_error(self, tool_name: str, error: str):
        self.ui.write_log(f"ERR: {tool_name} failed — see Debug Logs for details.")
        self.speak(f"Sir, {tool_name} encountered an error.")

    def _build_config(self) -> types.LiveConnectConfig:
        from datetime import datetime

        # Load customization from config
        try:
            _cfg = json.loads(open(API_CONFIG_PATH, encoding="utf-8").read())
            self._asst_name = (_cfg.get("assistant_name") or "JARVIS").strip()
            _user_name = (_cfg.get("user_name") or "").strip()
            self._barge_in_enabled = bool(_cfg.get("barge_in_enabled", False))
            self._phone_barge_in_enabled = bool(
                _cfg.get("phone_barge_in_enabled", True)
            )
        except Exception:
            self._asst_name = "JARVIS"
            _user_name = ""
            self._barge_in_enabled = False
            self._phone_barge_in_enabled = True

        memory     = load_memory()
        mem_str    = format_memory_for_prompt(memory)
        sys_prompt = _load_system_prompt()

        now      = datetime.now()
        time_str = now.strftime("%A, %B %d, %Y — %I:%M %p")
        time_ctx = (
            f"[CURRENT DATE & TIME]\n"
            f"Right now it is: {time_str}\n"
            f"Use this to calculate exact times for reminders.\n\n"
        )

        # Identity injection — overrides any hardcoded name in prompt.txt
        _addr = (f"ADDRESS: Always call the user '{_user_name}'."
                 if _user_name
                 else "ADDRESS: When speaking Turkish → always say \"efendim\". "
                      "When speaking English → say \"sir\". Never mix languages.")
        identity_ctx = (
            f"[IDENTITY]\n"
            f"Your name is {self._asst_name}. "
            f"Always refer to yourself as {self._asst_name}.\n"
            f"{_addr}\n\n"
        )

        parts = [time_ctx, identity_ctx]
        if mem_str:
            parts.append(mem_str)
        parts.append(sys_prompt)

        return types.LiveConnectConfig(
            response_modalities=[types.Modality.AUDIO],
            output_audio_transcription=types.AudioTranscriptionConfig(),
            input_audio_transcription=types.AudioTranscriptionConfig(),
            system_instruction="\n".join(parts),
            tools=[{"function_declarations": TOOL_DECLARATIONS}],
            realtime_input_config=types.RealtimeInputConfig(
                automatic_activity_detection=types.AutomaticActivityDetection(
                    disabled=False,
                    start_of_speech_sensitivity=(
                        types.StartSensitivity.START_SENSITIVITY_LOW
                    ),
                    end_of_speech_sensitivity=(
                        types.EndSensitivity.END_SENSITIVITY_HIGH
                    ),
                    prefix_padding_ms=40,
                    silence_duration_ms=300,
                ),
                activity_handling=(
                    types.ActivityHandling.START_OF_ACTIVITY_INTERRUPTS
                ),
                turn_coverage=types.TurnCoverage.TURN_INCLUDES_ONLY_ACTIVITY,
            ),
            # Native audio accumulates context quickly. Compression avoids the
            # hard 15-minute audio-session limit without client-side summaries.
            context_window_compression=types.ContextWindowCompressionConfig(
                sliding_window=types.SlidingWindow()
            ),
            session_resumption=types.SessionResumptionConfig(
                handle=self._resumption_handle
            ),
            # Gemini 2.5 uses a token budget. Zero keeps conversational replies
            # fast; tools still handle work that requires longer computation.
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            enable_affective_dialog=True,
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name="Charon"
                    )
                )
            ),
        )

    async def _legacy_direct_tool_dispatch(self, fc) -> types.FunctionResponse:
        """Retained only as rollback code until the Milestone 9 staged cutover."""
        name = fc.name
        args = dict(fc.args or {})
        trace_id = self._active_trace_id or self.logger.new_trace_id()
        started = time.monotonic()
        self.logger.log(
            "info", "tool_router", "tool_call", f"Tool requested: {name}.",
            trace_id=trace_id, tool_name=name, arguments=args,
        )
        self.logger.log(
            "debug", "tool_router", "system", f"Tool started: {name}.",
            trace_id=trace_id, tool_name=name,
        )
        self.ui.write_log(f"ACTION: {name} started.")

        print(f"[JARVIS] 🔧 {name}  {args}")
        self.ui.set_state("THINKING")

        if name == "save_memory":
            category = args.get("category", "notes")
            key      = args.get("key", "")
            value    = args.get("value", "")
            if key and value:
                update_memory({category: {key: {"value": value}}})
                print(f"[Memory] 💾 save_memory: {category}/{key} = {value}")
            self.logger.log(
                "info", "memory", "tool_result", "Memory update completed.",
                trace_id=trace_id, tool_name=name, arguments=args,
                result={"saved": bool(key and value)}, duration_ms=(time.monotonic() - started) * 1000,
            )
            if not self.ui.muted:
                self.ui.set_state("LISTENING")
            return types.FunctionResponse(
                id=fc.id, name=name,
                response={"result": "ok", "silent": True}
            )

        loop   = asyncio.get_event_loop()
        result = "Done."

        try:
            if name == "open_app":
                r = await loop.run_in_executor(None, lambda: open_app(parameters=args, response=None, player=self.ui))
                result = r or f"Opened {args.get('app_name')}."

            elif name == "weather_report":
                r = await loop.run_in_executor(None, lambda: weather_action(parameters=args, player=self.ui))
                result = r or "Weather delivered."

            elif name == "browser_control":
                r = await loop.run_in_executor(None, lambda: browser_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "file_controller":
                r = await loop.run_in_executor(None, lambda: file_controller(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "send_message":
                r = await loop.run_in_executor(None, lambda: send_message(parameters=args, response=None, player=self.ui, session_memory=None))
                result = r or f"Message sent to {args.get('receiver')}."

            elif name == "reminder":
                r = await loop.run_in_executor(None, lambda: reminder(parameters=args, response=None, player=self.ui))
                result = r or "Reminder set."

            elif name == "youtube_video":
                r = await loop.run_in_executor(None, lambda: youtube_video(parameters=args, response=None, player=self.ui))
                result = r or "Done."

            elif name == "screen_process":
                import time as _t_mod
                _now = _t_mod.monotonic()
                _cooldown = 4.0  # seconds — covers echo window after speaking ends
                if self._vision_busy or (_now - self._vision_last_time) < _cooldown:
                    _wait = max(0, _cooldown - (_now - self._vision_last_time))
                    print(f"[Vision] ⏳ Cooldown active ({_wait:.1f}s remaining) — ignoring duplicate call")
                    result = "Vision is still processing the previous request. I will not call this again."
                else:
                    self._vision_busy      = True
                    self._vision_last_time = _now
                    angle     = args.get("angle", "screen").lower()
                    user_text = args.get("text", "What do you see?")
                    if angle == "camera":
                        img_b, mime_t = await loop.run_in_executor(None, _capture_camera)
                        self.ui.start_camera_stream()
                        self._vision_cam_active = True
                        print(f"[Vision] 📷 Camera: {len(img_b):,} bytes")
                        _stall = "camera"
                    else:
                        img_b, mime_t = await loop.run_in_executor(None, _capture_screen)
                        print(f"[Vision] 🖥️  Screen: {len(img_b):,} bytes")
                        _stall = "screen"
                    self._pending_vision = (img_b, mime_t, user_text, angle)
                    result = (
                        f"[VISION_ACTIVE] {_stall.capitalize()} captured. "
                        f"Immediately say ONE short natural sentence in the user's own language, "
                        f"telling them you are looking at their {_stall} right now. "
                        f"Do NOT describe or guess content — the actual image arrives in the NEXT message."
                    )

            elif name == "close_camera":
                self.ui.stop_camera_stream()
                result = "Camera closed."

            elif name == "computer_settings":
                r = await loop.run_in_executor(None, lambda: computer_settings(parameters=args, response=None, player=self.ui))
                result = r or "Done."

            elif name == "desktop_control":
                r = await loop.run_in_executor(None, lambda: desktop_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "code_helper":
                r = await loop.run_in_executor(None, lambda: code_helper(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "dev_agent":
                r = await loop.run_in_executor(None, lambda: dev_agent(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "web_search":
                r = await loop.run_in_executor(None, lambda: web_search_action(parameters=args, player=self.ui))
                result = r or "Done."
                # Mirror results to the on-screen content panel
                _mode = args.get("mode", "search")
                if r and not r.startswith("No results") and not r.startswith("Search failed"):
                    _query = args.get("query") or ", ".join(args.get("items", []))
                    _label = f"{_mode.upper()} — {_query[:38]}" if _query else _mode.upper()
                    self.ui.show_content(_label, r)
            elif name == "file_processor":
                if not args.get("file_path") and self.ui.current_file:
                    args["file_path"] = self.ui.current_file
                r = await loop.run_in_executor(
                    None,
                    lambda: file_processor(parameters=args, player=self.ui, speak=self.speak)
                )
                result = r or "Done."

            elif name == "computer_control":
                r = await loop.run_in_executor(None, lambda: computer_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "game_updater":
                r = await loop.run_in_executor(None, lambda: game_updater(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "flight_finder":
                r = await loop.run_in_executor(None, lambda: flight_finder(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "system_status":
                r = await loop.run_in_executor(None, get_system_status)
                result = str(r)

            elif name == "manage_monitor":
                action = args.get("action", "").lower().strip()
                topic  = args.get("topic", "").strip()
                if action == "add" and topic:
                    result = await asyncio.to_thread(add_monitor, topic)
                elif action == "remove" and topic:
                    result = await asyncio.to_thread(remove_monitor, topic)
                elif action == "list":
                    topics = await asyncio.to_thread(list_monitors)
                    result = ("Monitoring: " + ", ".join(topics)) if topics else "No topics are being monitored."
                else:
                    result = "Specify action (add/remove/list) and a topic."

            elif name == "shutdown_jarvis":
                self.ui.write_log("SYS: Shutdown requested.")
                async def _do_shutdown():
                    await self._save_session_summary()
                    if self.session:
                        try:
                            await self._send_text(
                                "Say a brief natural goodbye to the user."
                            )
                        except Exception:
                            pass
                    await asyncio.sleep(1.5)
                    await self._stop_coordination()
                    import os as _os
                    _os._exit(0)
                asyncio.create_task(_do_shutdown())

            else:
                result = f"Unknown tool: {name}"

        except Exception as e:
            result = f"Tool '{name}' failed: {e}"
            traceback.print_exc()
            self.logger.log(
                "error", "tool_router", "error", f"Tool failed: {name}.",
                trace_id=trace_id, tool_name=name, arguments=args,
                duration_ms=(time.monotonic() - started) * 1000, exception=e,
            )
            self.speak_error(name, e)

        if not self.ui.muted:
            self.ui.set_state("LISTENING")

        self.logger.log(
            "info", "tool_router", "tool_result", f"Tool completed: {name}.",
            trace_id=trace_id, tool_name=name,
            result={"status": "completed", "result_chars": len(str(result))},
            duration_ms=(time.monotonic() - started) * 1000,
        )
        self.ui.write_log(f"ACTION: {name} completed.")
        print(f"[JARVIS] 📤 {name} → {str(result)[:80]}")
        return types.FunctionResponse(
            id=fc.id, name=name,
            response={"result": result}
        )

    def _build_tool_adapters(self) -> ToolAdapterRegistry:
        def action(function, default, **fixed):
            async def handler(arguments):
                result = await asyncio.to_thread(
                    function, parameters=arguments, **fixed
                )
                return default(arguments) if not result and callable(default) else (
                    default if not result else result
                )

            return handler

        adapters = {
            "open_app": CallableToolAdapter(
                "open_app",
                action(
                    open_app,
                    lambda values: f"Opened {values.get('app_name')}.",
                    response=None,
                    player=self.ui,
                ),
            ),
            "weather_report": CallableToolAdapter(
                "weather_report",
                action(weather_action, "Weather delivered.", player=self.ui),
            ),
            "browser_control": CallableToolAdapter(
                "browser_control",
                action(browser_control, "Done.", player=self.ui),
            ),
            "file_controller": CallableToolAdapter(
                "file_controller",
                action(file_controller, "Done.", player=self.ui),
            ),
            "send_message": CallableToolAdapter(
                "send_message",
                action(
                    send_message,
                    "Message sent.",
                    response=None,
                    player=self.ui,
                    session_memory=None,
                ),
            ),
            "reminder": CallableToolAdapter(
                "reminder",
                action(reminder, "Reminder set.", response=None, player=self.ui),
            ),
            "youtube_video": CallableToolAdapter(
                "youtube_video",
                action(
                    youtube_video, "Done.", response=None, player=self.ui
                ),
            ),
            "screen_process": CallableToolAdapter(
                "screen_process", self._adapter_screen_process
            ),
            "close_camera": CallableToolAdapter(
                "close_camera", self._adapter_close_camera
            ),
            "computer_settings": CallableToolAdapter(
                "computer_settings",
                action(
                    computer_settings, "Done.", response=None, player=self.ui
                ),
            ),
            "desktop_control": CallableToolAdapter(
                "desktop_control",
                action(desktop_control, "Done.", player=self.ui),
            ),
            "code_helper": CallableToolAdapter(
                "code_helper",
                action(
                    code_helper, "Done.", player=self.ui, speak=self.speak
                ),
            ),
            "dev_agent": CallableToolAdapter(
                "dev_agent",
                action(dev_agent, "Done.", player=self.ui, speak=self.speak),
            ),
            "web_search": CallableToolAdapter(
                "web_search", self._adapter_web_search
            ),
            "file_processor": CallableToolAdapter(
                "file_processor",
                action(
                    file_processor, "Done.", player=self.ui, speak=self.speak
                ),
            ),
            "computer_control": CallableToolAdapter(
                "computer_control",
                action(computer_control, "Done.", player=self.ui),
            ),
            "game_updater": CallableToolAdapter(
                "game_updater",
                action(
                    game_updater, "Done.", player=self.ui, speak=self.speak
                ),
            ),
            "flight_finder": CallableToolAdapter(
                "flight_finder",
                action(flight_finder, "Done.", player=self.ui),
            ),
            "system_status": CallableToolAdapter(
                "system_status", self._adapter_system_status
            ),
            "manage_monitor": CallableToolAdapter(
                "manage_monitor", self._adapter_manage_monitor
            ),
            "shutdown_jarvis": CallableToolAdapter(
                "shutdown_jarvis", self._adapter_shutdown_jarvis
            ),
            "save_memory": CallableToolAdapter(
                "save_memory", self._adapter_save_memory
            ),
        }
        return ToolAdapterRegistry(adapters)

    async def _adapter_save_memory(self, arguments):
        category = arguments.get("category", "notes")
        key = arguments.get("key", "")
        value = arguments.get("value", "")
        if key and value:
            await asyncio.to_thread(
                update_memory, {category: {key: {"value": value}}}
            )
        return "ok" if key and value else "Memory update was incomplete."

    async def _adapter_screen_process(self, arguments):
        now = time.monotonic()
        cooldown = 4.0
        if self._vision_busy or (now - self._vision_last_time) < cooldown:
            return "Vision is still processing the previous request."
        self._vision_busy = True
        self._vision_last_time = now
        angle = arguments.get("angle", "screen").lower()
        user_text = arguments.get("text", "What do you see?")
        if angle == "camera":
            image, mime_type = await asyncio.to_thread(_capture_camera)
            self.ui.start_camera_stream()
            self._vision_cam_active = True
            source = "camera"
        else:
            image, mime_type = await asyncio.to_thread(_capture_screen)
            source = "screen"
        self._pending_vision = (image, mime_type, user_text, angle)
        return (
            f"[VISION_ACTIVE] {source.capitalize()} captured. "
            "The actual image arrives in the next message."
        )

    async def _adapter_close_camera(self, arguments):
        self.ui.stop_camera_stream()
        return "Camera closed."

    async def _adapter_web_search(self, arguments):
        result = await asyncio.to_thread(
            web_search_action, parameters=arguments, player=self.ui
        )
        result = result or "Done."
        mode = arguments.get("mode", "search")
        if result and not result.startswith(("No results", "Search failed")):
            query = arguments.get("query") or ", ".join(arguments.get("items", []))
            label = f"{mode.upper()} — {query[:38]}" if query else mode.upper()
            self.ui.show_content(label, result)
        return result

    async def _adapter_system_status(self, arguments):
        return str(await asyncio.to_thread(get_system_status))

    async def _adapter_manage_monitor(self, arguments):
        operation = arguments.get("action", "").lower().strip()
        topic = arguments.get("topic", "").strip()
        if operation == "add" and topic:
            return await asyncio.to_thread(add_monitor, topic)
        if operation == "remove" and topic:
            return await asyncio.to_thread(remove_monitor, topic)
        if operation == "list":
            topics = await asyncio.to_thread(list_monitors)
            return "Monitoring: " + ", ".join(topics) if topics else "No topics are being monitored."
        return "Specify action and a topic."

    async def _adapter_shutdown_jarvis(self, arguments):
        self.ui.write_log("SYS: Shutdown requested.")

        async def shutdown():
            await self._save_session_summary()
            if self.session:
                try:
                    await self._send_text("Say a brief natural goodbye to the user.")
                except Exception:
                    pass
            await asyncio.sleep(1.5)
            await self._stop_coordination()
            import os as local_os
            local_os._exit(0)

        asyncio.create_task(shutdown())
        return "Shutdown scheduled."

    async def _execute_tool(self, fc) -> types.FunctionResponse:
        name = fc.name
        arguments = dict(fc.args or {})
        if name == "file_processor" and not arguments.get("file_path"):
            if self.ui.current_file:
                arguments["file_path"] = self.ui.current_file
        trace_id = self._active_trace_id or self.logger.new_trace_id()
        started = time.monotonic()
        self.ui.set_state("THINKING")
        self.logger.log(
            "info", "execution_gateway", "tool_request",
            f"Gateway request received for {name}.",
            trace_id=trace_id,
            tool_name=name,
        )
        intake = self._tool_intake
        if intake is None:
            result = "The safety gateway is not available; the action was not executed."
            disposition = "gateway_unavailable"
        else:
            try:
                gateway_result = await intake.execute(
                    session_id=self.logger.session_id,
                    trace_id=trace_id,
                    call_id=str(fc.id or self.logger.new_trace_id()),
                    tool_name=name,
                    arguments=arguments,
                )
                disposition = gateway_result.disposition.value
                if gateway_result.disposition is GatewayDisposition.EXECUTED:
                    result = gateway_result.output or "Done."
                    self.ui.write_log(f"ACTION: {name} completed through safety gateway.")
                elif gateway_result.disposition is GatewayDisposition.APPROVAL_REQUIRED:
                    result = (
                        "This action requires confirmation in the trusted desktop "
                        "approval interface and was not executed."
                    )
                    self.ui.write_log(
                        f"APPROVAL: {name} is waiting for trusted confirmation."
                    )
                elif gateway_result.disposition is GatewayDisposition.REPLAYED:
                    result = "This action was already processed and was not repeated."
                elif gateway_result.disposition is GatewayDisposition.OUTCOME_UNKNOWN:
                    result = (
                        "The action outcome could not be proven. It will not be retried "
                        "without verification."
                    )
                elif gateway_result.disposition is GatewayDisposition.FAILED:
                    result = "The action failed safely; see Debug Logs."
                else:
                    result = "Safety policy denied this action; it was not executed."
            except Exception as exc:
                disposition = "gateway_error"
                result = "The safety gateway failed closed; the action was not executed."
                self.logger.log(
                    "error", "execution_gateway", "gateway_error",
                    "Tool gateway failed closed.",
                    trace_id=trace_id,
                    tool_name=name,
                    result={"error_type": type(exc).__name__},
                )
        if not self.ui.muted:
            self.ui.set_state("LISTENING")
        self.logger.log(
            "info", "execution_gateway", "tool_result",
            f"Gateway request finished for {name}.",
            trace_id=trace_id,
            tool_name=name,
            result={"disposition": disposition, "result_chars": len(str(result))},
            duration_ms=(time.monotonic() - started) * 1000,
        )
        return types.FunctionResponse(
            id=fc.id,
            name=name,
            response={"result": result},
        )

    async def _send_realtime(self):
        while True:
            audio_bytes = await self.out_queue.get()
            if not self.session or not self._send_lock:
                continue
            async with self._send_lock:
                await self.session.send_realtime_input(
                    audio=types.Blob(
                        data=audio_bytes,
                        mime_type=INPUT_AUDIO_MIME,
                    )
                )
            self._audio_stream_ended = False

    def _pc_mic_allowed(self) -> bool:
        with self._speaking_lock:
            speaking = self._is_speaking
        return (
            not self.ui.muted
            and not self._phone_active
            and (not speaking or self._barge_in_enabled)
        )

    def _phone_mic_allowed(self) -> bool:
        with self._speaking_lock:
            speaking = self._is_speaking
        return (
            not self.ui.muted
            and (not speaking or self._phone_barge_in_enabled)
        )

    async def _sync_audio_stream_state(self) -> None:
        """Flush server-side audio when all microphones pause for >1 second."""
        was_streaming = False
        paused_at: float | None = None
        while True:
            streaming = self._pc_mic_allowed() or (
                self._phone_active and self._phone_mic_allowed()
            )
            if streaming:
                paused_at = None
                self._audio_stream_ended = False
            elif was_streaming:
                paused_at = time.monotonic()
            elif paused_at and time.monotonic() - paused_at >= 1.0:
                _drain_async_queue(self.out_queue)
                try:
                    await self._send_audio_stream_end()
                except Exception as exc:
                    print(f"[JARVIS] Audio stream-end warning: {exc}")
                paused_at = None
            was_streaming = streaming
            await asyncio.sleep(0.05)

    async def _listen_audio(self):
        print("[JARVIS] 🎤 Mic started")
        loop = asyncio.get_event_loop()

        def callback(indata, frames, time_info, status):
            if self._pc_mic_allowed():
                data = indata.tobytes()
                loop.call_soon_threadsafe(
                    _put_latest, self.out_queue, data
                )

        try:
            with sd.InputStream(
                samplerate=SEND_SAMPLE_RATE,
                channels=CHANNELS,
                dtype="int16",
                blocksize=INPUT_CHUNK_FRAMES,
                latency="low",
                callback=callback,
            ):
                print("[JARVIS] 🎤 Mic stream open")
                while True:
                    await asyncio.sleep(0.1)
        except Exception as e:
            print(f"[JARVIS] ❌ Mic: {e}")
            raise

    async def _receive_audio(self):
        print("[JARVIS] 👂 Recv started")
        out_buf = ""
        in_buf  = ""

        try:
            while True:
                async for response in self.session.receive():

                    update = getattr(response, "session_resumption_update", None)
                    if update and update.resumable and update.new_handle:
                        self._resumption_handle = update.new_handle

                    go_away = getattr(response, "go_away", None)
                    if go_away is not None:
                        print(
                            "[JARVIS] Gemini connection rotation requested; "
                            f"time left: {go_away.time_left}"
                        )

                    sc = response.server_content
                    if sc and sc.interrupted is True:
                        drained = _drain_async_queue(self.audio_in_queue)
                        self._interrupted = False
                        out_buf = ""
                        self.set_speaking(False)
                        if self._turn_done_event:
                            self._turn_done_event.clear()
                        print(
                            f"[JARVIS] Server interruption — {drained} "
                            "playback chunks discarded"
                        )

                    # A server event can contain multiple audio parts. Process
                    # every part; response.data is retained as an SDK fallback.
                    audio_parts: list[bytes] = []
                    if sc and sc.model_turn:
                        for part in sc.model_turn.parts or []:
                            inline = getattr(part, "inline_data", None)
                            if inline and inline.data:
                                audio_parts.append(inline.data)
                    if not audio_parts and response.data:
                        audio_parts.append(response.data)

                    if not self._interrupted:
                        for audio_data in audio_parts:
                            if self._turn_done_event and self._turn_done_event.is_set():
                                self._turn_done_event.clear()
                            for offset in range(
                                0, len(audio_data), PLAYBACK_SLICE_BYTES
                            ):
                                _put_latest(
                                    self.audio_in_queue,
                                    audio_data[
                                        offset : offset + PLAYBACK_SLICE_BYTES
                                    ],
                                )

                    if sc:

                        if sc.output_transcription and sc.output_transcription.text:
                            out_buf = _merge_transcript(
                                out_buf, sc.output_transcription.text
                            )
                            if out_buf:
                                self.ui.update_transcript(
                                    "assistant", out_buf, final=False
                                )

                        if sc.input_transcription and sc.input_transcription.text:
                            merged = _merge_transcript(
                                in_buf, sc.input_transcription.text
                            )
                            if merged:
                                in_buf = merged
                                self._last_user_speech = time.monotonic()
                                self.ui.update_transcript(
                                    "user", in_buf, final=False
                                )

                        if sc.turn_complete:
                            if self._turn_done_event:
                                self._turn_done_event.set()

                            # If this turn_complete ends an interrupted response, clear the
                            # flag and skip all further processing for that turn.
                            if self._interrupted:
                                self._interrupted = False
                                in_buf  = ""
                                out_buf = ""
                                self.ui.update_transcript("user", "", final=True)
                                self.ui.update_transcript("assistant", "", final=True)
                                continue

                            full_in = in_buf.strip()
                            if full_in:
                                self._active_trace_id = self.logger.new_trace_id()
                                self.logger.log(
                                    "info", "voice", "user_input", "Voice input received.",
                                    trace_id=self._active_trace_id, arguments={"text": full_in},
                                )
                                self.ui.write_log(f"You: {full_in}")
                                self._session_log.append(f"User: {full_in}")
                                if self._dashboard:
                                    asyncio.create_task(self._dashboard.broadcast({
                                        "type": "log", "speaker": "user",
                                        "text": full_in,
                                        "ts": datetime.now().isoformat(),
                                    }))
                            in_buf = ""

                            full_out = out_buf.strip()
                            if full_out:
                                self.logger.log(
                                    "info", "voice", "agent_response", "Assistant response received.",
                                    trace_id=self._active_trace_id, result={"text": full_out},
                                )
                                self.ui.write_log(f"{self._asst_name}: {full_out}")
                                self._session_log.append(f"{self._asst_name}: {full_out}")
                                if self._dashboard:
                                    asyncio.create_task(self._dashboard.broadcast({
                                        "type": "log", "speaker": "jarvis",
                                        "text": full_out,
                                        "ts": datetime.now().isoformat(),
                                    }))
                            out_buf = ""

                            # Vision injection: model finished tool-response turn → now send the image
                            if self._pending_vision and self.session:
                                img_b, mime_t, question, angle = self._pending_vision
                                self._pending_vision = None
                                print(f"[Vision] 📤 {len(img_b):,} bytes (angle={angle}) → main session")
                                await self._send_video_prompt(
                                    img_b, mime_t, question
                                )
                                # Mark next turn_complete behaviour depending on angle
                                if self._vision_cam_active:
                                    # Camera: keep busy until JARVIS finishes speaking the answer
                                    self._vision_cam_active    = False
                                    self._vision_close_pending = True
                                else:
                                    # Screen-only: no camera to close; release busy flag now
                                    self._vision_busy = False
                            elif self._vision_close_pending:
                                # This turn_complete IS the vision answer — close camera + release busy flag
                                self._vision_close_pending = False
                                self._vision_busy = False
                                async def _cam_close():
                                    await asyncio.sleep(2.0)
                                    self.ui.stop_camera_stream()
                                asyncio.create_task(_cam_close())

                    if response.tool_call:
                        fn_responses = []
                        for fc in response.tool_call.function_calls:
                            self.logger.log(
                                "info", "tool_router", "tool_call", f"Model requested tool: {fc.name}.",
                                trace_id=self._active_trace_id, tool_name=fc.name,
                            )
                            print(f"[JARVIS] 📞 {fc.name}")
                            fr = await self._execute_tool(fc)
                            fn_responses.append(fr)
                        async with self._send_lock:
                            await self.session.send_tool_response(
                                function_responses=fn_responses
                            )
        except Exception as e:
            print(f"[JARVIS] ❌ Recv: {e}")
            traceback.print_exc()
            raise

    async def _play_audio(self):
        print("[JARVIS] 🔊 Play started")

        stream = sd.RawOutputStream(
            samplerate=RECEIVE_SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=0,
            latency="low",
        )
        stream.start()

        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        self.audio_in_queue.get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    if (
                        self._turn_done_event
                        and self._turn_done_event.is_set()
                        and self.audio_in_queue.empty()
                    ):
                        self.set_speaking(False)
                        self._turn_done_event.clear()
                    continue

                self.set_speaking(True)

                # Batch a few slices to reduce executor overhead while retaining
                # sub-100 ms interruption response.
                batch = bytearray(chunk)
                while len(batch) < PLAYBACK_BATCH_BYTES:
                    try:
                        batch.extend(self.audio_in_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                try:
                    await asyncio.to_thread(stream.write, bytes(batch))
                except (RuntimeError, asyncio.CancelledError):
                    break   # executor shutting down — exit cleanly
        except Exception as e:
            print(f"[JARVIS] ❌ Play: {e}")
            raise
        finally:
            self.set_speaking(False)
            stream.stop()
            stream.close()

    # ── Morning briefing ────────────────────────────────────────────────────────

    async def _send_startup_briefing(self) -> None:
        """
        Two-phase briefing optimized for speed:
          Phase 1 — instant greeting (no tools) → speech starts in <1s
          Phase 2 — news pre-fetched in a background thread while Phase 1 plays,
                    delivered as ready text (no Gemini tool-call round-trip) and
                    shown on the UI content panel. Waits for turn_complete event
                    instead of a fixed sleep so there is no unnecessary gap.
        """
        memory   = load_memory()
        identity = memory.get("identity", {})

        def _val(k: str) -> str:
            e = identity.get(k, {})
            return (e.get("value", "") if isinstance(e, dict) else str(e)).strip()

        lang = _val("language")
        name = _val("name")
        time_str = datetime.now().strftime("%H:%M")

        # Start fetching news immediately — runs in parallel while phase 1 plays
        loop = asyncio.get_event_loop()
        news_future = loop.run_in_executor(None, _fetch_news_sync, "top world news today")

        await asyncio.sleep(0.3)
        if not self.session:
            return

        # ── Phase 1: instant greeting ─────────────────────────────────────────
        lang_clause = f" Respond in {lang}." if lang else ""
        name_clause = f" Address the user as {name}." if name else ""

        # Inject last session context if available — pop removes it so it's never repeated
        last = await asyncio.to_thread(pop_last_session)
        session_clause = ""
        if last:
            try:
                _delta = (datetime.now() - datetime.strptime(last["date"], "%Y-%m-%d")).days
                _when  = "earlier today" if _delta == 0 else ("yesterday" if _delta == 1 else f"{_delta} days ago")
            except Exception:
                _when = "last time"
            session_clause = (
                f" Also briefly and naturally mention that {_when}: {last['summary']}"
            )

        p1 = (
            f"Greet the user warmly, mention it is {time_str}, and say you are fetching today's news now.{session_clause} "
            f"Keep it to 2 short sentences max. Do not call any tools.{lang_clause}{name_clause}"
        )

        # Clear the turn-done event so we can wait for Phase 1 to finish
        if self._turn_done_event:
            self._turn_done_event.clear()

        await self._send_text(p1)
        self.ui.write_log("SYS: Briefing phase 1 (greeting) sent.")

        # ── Phase 2: fire as soon as Phase 1 audio is done ───────────────────
        async def _deliver_news():
            try:
                lang_str = f" Respond in {lang}." if lang else ""

                # Wait for news fetch (already running) and Phase 1 turn-complete
                # in parallel — whichever takes longer determines the wait time
                news_done   = asyncio.wrap_future(news_future)
                turn_waited = False
                if self._turn_done_event:
                    try:
                        await asyncio.wait_for(self._turn_done_event.wait(), timeout=6.0)
                        turn_waited = True
                    except asyncio.TimeoutError:
                        pass

                # Extra buffer: turn_complete fires when Gemini finishes *generating*
                # Phase 1, but audio may still be playing.  Waiting a beat here
                # prevents Phase 2 audio from arriving while Phase 1 is mid-sentence
                # (which sounds like a "repeated first response" to the user).
                if turn_waited:
                    await asyncio.sleep(0.8)
                else:
                    await asyncio.sleep(1.0)

                try:
                    news_text = await asyncio.wait_for(news_done, timeout=4.0)
                except Exception:
                    news_text = ""

                if not self.session:
                    return

                if news_text and len(news_text) > 60:
                    # Show on UI content panel immediately
                    self.ui.show_content("NEWS — top world news today", news_text)

                    p2 = (
                        f"[BRIEFING] Here are today's top news headlines:\n{news_text}\n\n"
                        "Pick ONE headline, summarise it in one sentence, then say the full list "
                        f"is displayed on screen. Do not call any tools.{lang_str}"
                    )
                else:
                    p2 = (
                        "News headlines could not be fetched right now. "
                        f"Let the user know briefly.{lang_str}"
                    )

                await self._send_text(p2)
                self.ui.write_log("SYS: Briefing phase 2 (news) sent.")
            except Exception as e:
                print(f"[Briefing] Phase 2 error: {e}")
                self.ui.write_log(f"SYS: Briefing phase 2 failed: {e}")

        asyncio.create_task(_deliver_news())

    # ── Session memory ──────────────────────────────────────────────────────────

    async def _save_session_summary(self) -> None:
        """Summarise the current session in 1-2 sentences and save to long_term.json."""
        log = self._session_log
        if len(log) < 3:          # need at least one exchange to be worth saving
            return
        self._session_log = []    # reset immediately so the next session starts clean

        memory = load_memory()
        lang_entry = memory.get("identity", {}).get("language", {})
        lang = (lang_entry.get("value", "") if isinstance(lang_entry, dict) else str(lang_entry)).strip()
        lang = lang or "English"

        convo = "\n".join(log[-40:])   # cap at last 40 turns to stay within token budget
        prompt = (
            f"Summarize this conversation in 1-2 sentences in {lang}. "
            "Focus on what the user accomplished or discussed. "
            "Output ONLY the summary text, nothing else:\n\n" + convo
        )
        try:
            from google import genai as _genai
            client = _genai.Client(api_key=_get_api_key())
            resp   = await asyncio.to_thread(
                client.models.generate_content,
                model=ORCHESTRATOR_CONFIG.models.planner.name,
                contents=prompt,
            )
            summary = (resp.text or "").strip()
            if summary:
                save_session_summary(summary, lang)
                self.logger.log("info", "memory", "system", "Session summary saved.")
        except Exception as e:
            print(f"[Memory] ⚠️ Session summary failed: {e}")

    # ── System monitor ──────────────────────────────────────────────────────────

    async def _run_system_monitor(self) -> None:
        """Background task: voice alerts when metrics exceed thresholds."""
        self.logger.log("debug", "scheduler", "system", "System monitor started.")
        while True:
            await asyncio.sleep(10)
            alert = await asyncio.to_thread(self._sys_monitor.check)
            if not alert or not self.session:
                continue
            # Don't interrupt an active conversation
            with self._speaking_lock:
                speaking = self._is_speaking
            if speaking or (time.monotonic() - self._last_user_speech) < 10:
                continue
            try:
                await self._send_text(alert)
            except Exception as e:
                print(f"[Monitor] ⚠️ Could not send alert: {e}")

    # ── Background monitor ──────────────────────────────────────────────────────

    async def _run_background_monitor(self) -> None:
        """Check user-configured topics once per day; speak alerts when new headlines appear."""
        self.logger.log("debug", "scheduler", "system", "Background monitor started.")
        await asyncio.sleep(300)          # wait 5 min after startup before first check
        while True:
            if self.session:
                # Don't interrupt if user spoke recently or JARVIS is mid-sentence
                with self._speaking_lock:
                    speaking = self._is_speaking
                recent_speech = (time.monotonic() - self._last_user_speech) < 30
                if not speaking and not recent_speech:
                    try:
                        alerts = await asyncio.to_thread(monitor_check_all)
                        memory = load_memory()
                        lang_e = memory.get("identity", {}).get("language", {})
                        lang   = (lang_e.get("value", "") if isinstance(lang_e, dict) else str(lang_e)).strip() or "English"
                        for alert in alerts:
                            msg = (
                                f"{alert}\n\n"
                                f"Inform the user about this development naturally in {lang}. "
                                "One brief sentence only."
                            )
                            await self._send_text(msg)
                            self.ui.write_log(f"SYS: Monitor alert sent.")
                            await asyncio.sleep(6)   # gap between consecutive alerts
                    except Exception as e:
                        print(f"[Monitor] ⚠️ Background check error: {e}")
            await asyncio.sleep(1800)     # check every 30 minutes

    # ── Proactive mode ──────────────────────────────────────────────────────────

    async def _run_proactive_mode(self) -> None:
        """
        Background task: periodically checks if the user has been silent long enough,
        then hands time + memory context to Gemini so it can decide what (if anything)
        to say proactively. No hardcoded rules — Gemini makes the call.
        """
        self.logger.log("debug", "scheduler", "system", "Proactive scheduler started.")
        while True:
            await asyncio.sleep(60)   # evaluate once per minute

            if not self.session:
                continue

            with self._speaking_lock:
                speaking = self._is_speaking
            if speaking:
                continue

            if not self._proactive.should_trigger(self._last_user_speech):
                continue

            self._proactive.mark_triggered()

            try:
                memory       = await asyncio.to_thread(load_memory)
                monitors     = await asyncio.to_thread(list_monitors)
                recent_turns = self._session_log[-8:] if self._session_log else []
                prompt = self._proactive.build_prompt(
                    memory       = memory,
                    monitors     = monitors or None,
                    recent_turns = recent_turns or None,
                )
                await self._send_text(prompt)
                self.ui.write_log("SYS: Proactive check-in.")
            except Exception as e:
                print(f"[Proactive] ⚠️ {e}")

    # ── Phone audio relay ────────────────────────────────────────────────────────

    async def _relay_phone_audio(self) -> None:
        """Forward phone mic PCM chunks from dashboard queue into the Gemini Live session."""
        q = self._dashboard._phone_audio_queue
        while True:
            try:
                chunk = await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # No audio for 1 s → phone mic inactive, give PC mic back
                self._phone_active = False
                continue
            self._phone_active = True   # phone is streaming — silence PC mic
            if self._phone_mic_allowed():
                _put_latest(self.out_queue, chunk["data"])

    def _on_phone_connected(self) -> None:
        self.ui.write_log("SYS: Phone connected via Remote Dashboard.")
        self.ui.notify_phone_connected()

    # ── dashboard command relay ─────────────────────────────────────────────

    async def _process_dashboard_commands(self) -> None:
        while True:
            try:
                text = await asyncio.wait_for(
                    self._dashboard._command_queue.get(), timeout=0.5
                )
                if not text:
                    continue
                # Wait up to 8s for session to become ready after a wake
                for _ in range(80):
                    if self.session:
                        break
                    await asyncio.sleep(0.1)
                if self.session:
                    await self._send_text(text)
                    self.ui.write_log(f"[Web]: {text}")
                else:
                    print(f"[Dashboard] Dropped command (no session): {text}")
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                print(f"[Dashboard] Command error: {e}")
                await asyncio.sleep(0.5)

    # ── main loop ───────────────────────────────────────────────────────────

    def _report_coordination_health(self, health: CoordinationHealth) -> None:
        result = {
            "mode": health.mode.value,
            "redis_available": health.redis_available,
            "circuit_state": health.circuit_state.value,
            "consecutive_failures": health.consecutive_failures,
            "reason_code": health.reason_code,
        }
        if health.mode is CoordinationMode.REDIS:
            self.logger.log(
                "info", "coordination", "coordination_health",
                "Redis coordination connected.", result=result,
            )
            self.ui.write_log("SYS: Redis coordination connected.")
            return

        reason = health.reason_code or "redis_unavailable"
        self.logger.log(
            "warn", "coordination", "coordination_health",
            "Redis coordination unavailable; SQLite degraded mode active.",
            result=result,
        )
        self.ui.write_log(
            f"WARN: Redis unavailable ({reason}); SQLite degraded mode active."
        )

    def _report_coordination_error(self, exc: Exception) -> None:
        self.logger.log(
            "error", "coordination", "coordination_monitor_error",
            "Coordination health monitor failed unexpectedly.",
            result={"error_type": type(exc).__name__},
        )

    async def _start_coordination(self) -> None:
        try:
            self._coordination = create_application_coordination(
                BASE_DIR,
                ORCHESTRATOR_CONFIG,
                on_health=self._report_coordination_health,
                on_error=self._report_coordination_error,
            )
            await self._coordination.start()
            adapters = self._build_tool_adapters()
            self._execution_gateway = ExecutionGateway(
                self._coordination.runtime.store,
                adapters,
                ORCHESTRATOR_CONFIG,
            )
            self._tool_intake = LegacyToolIntake(
                self._coordination.runtime.store,
                self._execution_gateway,
            )
        except Exception as exc:
            self.logger.log(
                "error", "coordination", "coordination_startup_failed",
                "Coordination startup failed.",
                result={"error_type": type(exc).__name__},
            )
            self.ui.write_log("ERR: Coordination startup failed; check Debug Logs.")
            raise

    async def _stop_coordination(self) -> None:
        self._tool_intake = None
        self._execution_gateway = None
        lifecycle = self._coordination
        self._coordination = None
        if lifecycle is None:
            return
        try:
            await lifecycle.stop()
            self.logger.log(
                "info", "coordination", "coordination_stopped",
                "Redis coordination stopped cleanly.",
            )
        except Exception as exc:
            self.logger.log(
                "warn", "coordination", "coordination_shutdown_failed",
                "Redis coordination shutdown reported an error.",
                result={"error_type": type(exc).__name__},
            )

    async def run(self):
        self._loop = asyncio.get_event_loop()
        try:
            await self._start_coordination()
            await self._run_application()
        finally:
            await self._stop_coordination()

    async def _run_application(self):
        self._loop = asyncio.get_event_loop()
        self.logger.log("info", "system", "system", "JARVIS runtime started.")

        # Start dashboard (optional — needs: pip install fastapi "uvicorn[standard]" cryptography)
        try:
            from dashboard.server import DashboardServer
            self._dashboard = DashboardServer()
            self._dashboard.set_connect_callback(self._on_phone_connected)
            asyncio.create_task(self._dashboard.serve())
            # Runs for the whole lifetime, not just inside an active session
            asyncio.create_task(self._process_dashboard_commands())
        except Exception as e:
            print(f"[Dashboard] Disabled: {e}")
            self._dashboard = None

        while True:
            try:
                print("[JARVIS] Connecting...")
                self.ui.set_state("THINKING")
                config = self._build_config()

                # Fresh client on every reconnect — avoids stale HTTP session state
                client = genai.Client(
                    api_key=_get_api_key(),
                    http_options={"api_version": "v1beta"}
                )

                if (
                    ORCHESTRATOR_CONFIG.capability_checks.enabled
                    and not self._model_capabilities_checked
                ):
                    provider = (
                        GoogleModelMetadataProvider(client)
                        if ORCHESTRATOR_CONFIG.capability_checks.remote_metadata_check
                        else None
                    )
                    capability_report = await asyncio.to_thread(
                        check_model_capabilities,
                        ORCHESTRATOR_CONFIG,
                        provider,
                    )
                    for check in capability_report.checks:
                        self.logger.log(
                            "warn" if check.status is CapabilityStatus.WARNING else (
                                "error" if check.status is CapabilityStatus.FAIL else "info"
                            ),
                            "model_registry",
                            "model_capability_check",
                            f"Model capability check {check.status.value}: {check.role.value}.",
                            result={
                                "model_name": check.model_name,
                                "status": check.status.value,
                                "missing": sorted(item.value for item in check.missing),
                                "remote_checked": check.remote_checked,
                            },
                        )
                    fatal_local = any(
                        check.status is CapabilityStatus.FAIL and not check.remote_checked
                        for check in capability_report.checks
                    )
                    fatal_remote = any(
                        check.status is CapabilityStatus.FAIL and check.remote_checked
                        for check in capability_report.checks
                    )
                    if (
                        fatal_local
                        and ORCHESTRATOR_CONFIG.capability_checks.fail_startup_on_local_mismatch
                    ) or (
                        fatal_remote
                        and ORCHESTRATOR_CONFIG.capability_checks.fail_startup_on_remote_unavailable
                    ):
                        raise RuntimeError("Configured model capability validation failed.")
                    self._model_capabilities_checked = True

                async with (
                    client.aio.live.connect(model=LIVE_MODEL, config=config) as session,
                    asyncio.TaskGroup() as tg,
                ):
                    self.session          = session
                    self.audio_in_queue   = asyncio.Queue(
                        maxsize=PLAYBACK_QUEUE_MAX
                    )
                    self.out_queue        = asyncio.Queue(
                        maxsize=INPUT_QUEUE_MAX
                    )
                    self._send_lock       = asyncio.Lock()
                    self._turn_done_event = asyncio.Event()

                    # Reset transient state that must not carry over from a previous session
                    self._pending_vision       = None
                    self._vision_cam_active    = False
                    self._vision_close_pending = False
                    self._vision_busy          = False
                    self._vision_last_time     = 0.0
                    self._interrupted          = False
                    self._audio_stream_ended   = False

                    print("[JARVIS] Connected.")
                    self._conn_backoff = 3
                    self.logger.log("info", "system", "system", "Live session connected.")
                    self.ui.set_state("LISTENING")
                    self.ui.write_log("SYS: JARVIS online.")

                    if self._dashboard:
                        await self._dashboard.broadcast({"type": "status", "state": "active"})

                    tg.create_task(self._send_realtime())
                    tg.create_task(self._listen_audio())
                    tg.create_task(self._sync_audio_stream_state())
                    tg.create_task(self._receive_audio())
                    tg.create_task(self._play_audio())
                    tg.create_task(self._run_system_monitor())
                    tg.create_task(self._run_background_monitor())
                    tg.create_task(self._run_proactive_mode())
                    if self._dashboard:
                        tg.create_task(self._relay_phone_audio())

                    # Morning briefing — fires once per process launch (if enabled)
                    if not self._briefing_sent and get_brief_enabled():
                        self._briefing_sent = True
                        tg.create_task(self._send_startup_briefing())

            except KeyboardInterrupt:
                raise
            except SystemExit:
                raise
            except BaseException as e:
                # Catches both Exception and BaseExceptionGroup (Python 3.11+
                # TaskGroup raises BaseExceptionGroup when tasks are cancelled
                # externally, which `except Exception` would miss, letting the
                # exception escape the while-loop and causing asyncio.run() to
                # start shutdown — resulting in "executor after shutdown" errors).
                err_str = str(e)
                print(f"[JARVIS] Error ({type(e).__name__}): {e}")
                traceback.print_exc()
                self.logger.log(
                    "error", "system", "error", "Live session error.", exception=e,
                )

                if self._resumption_handle and any(
                    marker in err_str.lower()
                    for marker in ("resumption handle", "session resumption")
                ):
                    # A stale/expired handle must not poison every reconnect.
                    self._resumption_handle = None
                    self.ui.write_log(
                        "SYS: Previous voice session expired — starting fresh."
                    )

                # Invalid API key — stop hammering the API, prompt re-configuration
                if "API key not valid" in err_str or "1007" in err_str:
                    self.ui.write_log("ERR: API key invalid — please re-enter your key.")
                    self.ui.set_state("SLEEPING")
                    self.ui.prompt_reconfig()
                    while not self.ui._win._ready:
                        await asyncio.sleep(1)
                    print("[JARVIS] New API key saved — reconnecting...")
                    _conn_backoff = 3
                    continue

                # Network / timeout errors — log clearly and back off
                is_net_err = any(k in err_str for k in (
                    "TimeoutError", "timed out", "getaddrinfo", "CancelledError",
                    "ConnectionRefusedError", "OSError", "Cannot connect",
                ))
                if is_net_err:
                    _conn_backoff = min(getattr(self, "_conn_backoff", 3) * 2, 60)
                    self._conn_backoff = _conn_backoff
                    self.ui.write_log(
                        f"NET: Bağlantı kurulamadı — {_conn_backoff}s sonra tekrar deneniyor. "
                        "(VPN gerekiyor olabilir)"
                    )
                else:
                    self._conn_backoff = 3
            finally:
                self.session = None
                self._send_lock = None
                # Only save if there was a real conversation (≥3 turns)
                if len(self._session_log) >= 3:
                    asyncio.create_task(self._save_session_summary())

            self.set_speaking(False)
            self.ui.set_state("SLEEPING")

            if self._dashboard:
                await self._dashboard.broadcast({"type": "status", "state": "sleeping"})

            delay = getattr(self, "_conn_backoff", 3)
            print(f"[JARVIS] Reconnecting in {delay}s...")
            await asyncio.sleep(delay)

def main():
    ui = JarvisUI("face.png")

    def runner():
        ui.wait_for_api_key()
        jarvis = JarvisLive(ui)
        try:
            asyncio.run(jarvis.run())
        except KeyboardInterrupt:
            print("\n🔴 Shutting down...")
        finally:
            jarvis.logger.close()

    threading.Thread(target=runner, daemon=True).start()
    ui.root.mainloop()

if __name__ == "__main__":
    main()
