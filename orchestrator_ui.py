"""Trusted desktop task controls. Audit history deliberately excludes payloads."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QPlainTextEdit, QLineEdit, QComboBox, QSplitter, QWidget, QFileDialog)

from orchestrator.safety.policy import derive_exact_target

AUDIT_FIELDS = ('occurred_at', 'event_type', 'task_id', 'step_id', 'approval_id',
                'tool_name', 'worker_id', 'model_name', 'risk_level', 'outcome',
                'trace_id', 'new_state', 'error_code')


def build_task_snapshot(engine):
    """Read on the orchestrator thread; never expose event payloads or secrets."""
    tasks = list(engine.tasks())
    for task in tasks:
        with engine.store.database.read() as connection:
            task['checkpoints'] = [row[0] for row in connection.execute(
                "SELECT artifact_id FROM artifacts WHERE task_id=? AND kind='coding_checkpoint' ORDER BY created_at DESC",
                (task['task_id'],)).fetchall()]
            task['verification'] = [dict(row) for row in connection.execute(
                'SELECT step_id,verifier_type,result,created_at FROM verifications WHERE task_id=? ORDER BY created_at',
                (task['task_id'],)).fetchall()]
        try:
            plan = engine.plan(task['task_id'])
        except ValueError:
            task['plan'] = None
            task['audit'] = []
            continue
        task['plan'] = plan.model_dump(mode='json')
        task['audit'] = [{key: event.model_dump(mode='json').get(key)
                          for key in AUDIT_FIELDS} for event in engine.audit(task['task_id'])]
        for approval in task['approvals']:
            record = engine.store.get_approval(approval['approval_id'])
            approved_plan = engine.store.get_plan(record.plan_id, record.plan_version)
            step = next(step for step in approved_plan.steps if step.step_id == record.step_id)
            approval['plan_version'] = record.plan_version
            approval['reason'] = record.reason
            approval['tool_name'] = record.tool_name
            approval['arguments'] = step.proposal.arguments if step.proposal else {}
            approval['target'] = (derive_exact_target(record.tool_name, approval['arguments'])
                                  if step.proposal else None)
    return tasks


class TaskCenterDialog(QDialog):
    def __init__(self, parent=None, snapshot=None, action=None, assistant_name='Assistant'):
        super().__init__(parent)
        self.snapshot_callback, self.action_callback = snapshot, action
        self._pending = None
        self._action_pending = None
        self._tasks = []
        self._approval_dialog = None
        self.setWindowTitle(f'{assistant_name} — Tasks')
        self.resize(900, 650)
        self.setStyleSheet('QDialog, QWidget {background:#111820;color:#dce6ed;} '
            'QLineEdit,QPlainTextEdit,QListWidget,QComboBox {background:#18232d;border:1px solid #324454;padding:6px;} '
            'QPushButton {padding:7px 12px;border:1px solid #426277;border-radius:5px;} '
            'QPushButton:disabled {color:#61707b;}')
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.request = QLineEdit()
        self.request.setPlaceholderText('Describe a task to plan…')
        self.mode = QComboBox()
        self.mode.addItems(["Routine", "Coding", "Browser"])
        self.mode.currentTextChanged.connect(self._mode_changed)
        submit = QPushButton('Plan task')
        submit.clicked.connect(self._submit)
        row.addWidget(self.mode)
        row.addWidget(self.request, 1)
        row.addWidget(submit)
        layout.addLayout(row)
        options = QHBoxLayout()
        self.workspace = QLineEdit()
        self.workspace.setPlaceholderText("Select the project workspace")
        self.coding_mode = QComboBox()
        for label, value in [('Edit files', 'edit'), ('Explain code', 'explain'), ('Debug screenshot', 'debug'), ('Plan commands', 'commands')]:
            self.coding_mode.addItem(label, value)
        self.image_path = QLineEdit()
        self.image_path.setPlaceholderText('Screenshot path (debug mode only)')
        self.choose_image = QPushButton('Choose image')
        self.choose_image.clicked.connect(self._choose_image)
        self.coding_mode.currentIndexChanged.connect(lambda: self._mode_changed(self.mode.currentText()))
        self.browser_choice = QComboBox()
        self.browser_choice.addItems(['chromium', 'chrome', 'edge', 'firefox'])
        self.choose_workspace = QPushButton("Choose folder")
        self.choose_workspace.clicked.connect(self._choose_workspace)
        self.browser_url = QLineEdit()
        self.browser_url.setPlaceholderText("Starting HTTPS URL")
        self.domains = QLineEdit()
        self.domains.setPlaceholderText("Allowed domains, separated by commas")
        for widget in (self.workspace, self.choose_workspace, self.coding_mode, self.browser_url, self.domains, self.browser_choice):
            options.addWidget(widget)
            widget.hide()
        layout.addLayout(options)
        images = QHBoxLayout()
        images.addWidget(self.image_path, 1)
        images.addWidget(self.choose_image)
        self.image_path.hide()
        self.choose_image.hide()
        layout.addLayout(images)
        self.scope_note = QLabel()
        self.scope_note.setWordWrap(True)
        layout.addWidget(self.scope_note)
        self.notice = QLabel('Tasks run locally. Approvals require a desktop click.')
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        split = QSplitter()
        self.task_list = QListWidget()
        self.task_list.currentRowChanged.connect(self._render)
        split.addWidget(self.task_list)
        detail = QWidget()
        details = QVBoxLayout(detail)
        self.plan_view = QPlainTextEdit()
        self.plan_view.setReadOnly(True)
        details.addWidget(self.plan_view, 2)
        controls = QHBoxLayout()
        self.buttons = {}
        for name, title in [('approve_plan', 'Approve plan'), ('approve_step', 'Review action'),
                            ('pause', 'Pause'), ('resume', 'Resume'), ('cancel', 'Cancel')]:
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, name=name: self._control(name))
            controls.addWidget(button)
            self.buttons[name] = button
        details.addLayout(controls)
        worker_controls = QHBoxLayout()
        self.apply_code = QPushButton("Review applying diff")
        self.restore_code = QPushButton("Review restoring files")
        self.stop_browser = QPushButton("Stop browser")
        self.stop_all = QPushButton("Stop all tasks")
        self.load_checkpoint = QPushButton("Review saved checkpoint")
        self.review_commands = QPushButton('Review local commands')
        self.review_commands.clicked.connect(self._review_commands)
        self.load_checkpoint.clicked.connect(self._load_checkpoint)
        self.apply_code.clicked.connect(lambda: self._code_control("coding_apply"))
        self.restore_code.clicked.connect(lambda: self._code_control("coding_restore"))
        self.stop_browser.clicked.connect(self._stop_browser)
        self.stop_all.clicked.connect(lambda: self._dispatch("stop_all"))
        for button in (self.apply_code, self.restore_code, self.load_checkpoint, self.stop_browser, self.stop_all):
            worker_controls.addWidget(button)
        details.addLayout(worker_controls)
        details.addWidget(self.review_commands)
        filters = QHBoxLayout()
        self.filter_field = QComboBox()
        self.filter_field.addItems(['All fields', *AUDIT_FIELDS])
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText('Filter audit history…')
        self.filter_text.textChanged.connect(self._render_audit)
        self.filter_field.currentTextChanged.connect(self._render_audit)
        filters.addWidget(self.filter_field)
        filters.addWidget(self.filter_text, 1)
        details.addLayout(filters)
        self.audit_view = QPlainTextEdit()
        self.audit_view.setReadOnly(True)
        details.addWidget(self.audit_view, 1)
        split.addWidget(detail)
        split.setSizes([220, 680])
        layout.addWidget(split, 1)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()

    def _selected(self):
        index = self.task_list.currentRow()
        return self._tasks[index] if 0 <= index < len(self._tasks) else None

    def refresh(self):
        if not self.isVisible() and self._tasks:
            return
        if self._action_pending is not None and self._action_pending.done():
            try:
                self._action_pending.result()
                self.notice.setText('Task updated.')
            except Exception:
                self.notice.setText('Action could not complete. Refresh and review the task state.')
            self._action_pending = None
        if self._pending is not None:
            if not self._pending.done():
                return
            try:
                self.set_snapshot(self._pending.result())
            except Exception:
                self.notice.setText('Task history is unavailable. Try again shortly.')
            self._pending = None
        if self.snapshot_callback:
            try:
                self._pending = self.snapshot_callback()
            except Exception:
                self.notice.setText('Task service is unavailable.')

    def set_snapshot(self, tasks):
        current = self._selected()
        selected_id = current['task_id'] if current else None
        self._tasks = tasks
        self.task_list.blockSignals(True)
        self.task_list.clear()
        selected = 0
        for i, task in enumerate(tasks):
            self.task_list.addItem(f"{task['status'].replace('_', ' ')}\n{task['task_id'][:12]}")
            if task['task_id'] == selected_id:
                selected = i
        self.task_list.setCurrentRow(selected if tasks else -1)
        self.task_list.blockSignals(False)
        self._render()

    def _render(self, *_):
        task = self._selected()
        self.apply_code.setEnabled(False)
        self.restore_code.setEnabled(False)
        self.stop_browser.setEnabled(False)
        self.load_checkpoint.setEnabled(bool(task and task.get("checkpoints")))
        self.review_commands.setEnabled(bool(task and task.get('coding')))
        for button in self.buttons.values():
            button.setEnabled(False)
        if not task:
            self.plan_view.setPlainText('No tasks yet.')
            self.audit_view.clear()
            return
        status = task['status']
        plan = task.get('plan')
        lines = [f"Status: {status.replace('_', ' ')}"]
        for report in task.get('command_reports', []):
            lines.append(f"Local command exit: {report['exit_code']}; timed out: {report['timed_out']}\n{report['output']}")
        coding = task.get("coding")
        if coding and coding.get('inspection'):
            lines.append(coding['inspection']['explanation'])
            lines.append(json.dumps(coding['inspection']['commands'], indent=2))
        if coding:
            lines += ["", "Coding workspace: " + coding["workspace"], coding["summary"],
                      "Planned files: " + ", ".join(coding["files"]),
                      "Checks: " + "; ".join(coding["checks"]),
                      "File checks do not execute project code. Use a separately approved local command task for runtime tests."]
            if coding.get("git_status"):
                lines += ["Git status at discovery:", coding["git_status"]]
            if coding["diff"] is not None:
                lines += ["", "Exact proposed diff:", coding["diff"]]
            self.apply_code.setEnabled(coding["ready"] and not coding["applied"] and status == "completed")
            self.restore_code.setEnabled(coding["applied"] and status in {"completed", "paused", "failed", "cancelled"})
        self.stop_browser.setEnabled(bool(task.get("browser_session_id")))
        if plan:
            lines += [f"Plan {plan['version']}: {plan['summary']}", f"Risk: {plan['risk_summary']}", '']
            states = {step['step_id']: step['status'] for step in task['steps']}
            completed = sum(states.get(step['step_id']) == 'completed' for step in plan['steps'])
            lines.append(f"Progress: {completed}/{len(plan['steps'])} steps verified")
            for step in plan['steps']:
                dependencies = [edge['depends_on_step_id'] for edge in plan['dependencies']
                                if edge['step_id'] == step['step_id']]
                lines += [f"\n{step['step_id']} · {states.get(step['step_id'], 'planned')} · {step['risk']}",
                          step['action'], f"Expected: {step['expected_result']}"]
                if dependencies:
                    lines.append('Waits for: ' + ', '.join(dependencies))
                proposal = step.get('proposal')
                if proposal:
                    lines.append('Tool: ' + proposal['tool_name'])
                    lines.append('Target: ' + str(derive_exact_target(proposal['tool_name'], proposal['arguments'])))
                    lines.append('Final values: ' + json.dumps(proposal['arguments'], ensure_ascii=False, indent=2))
            for verification in task.get('verification', []):
                lines.append(f"Evidence check: {verification['step_id']} · {verification['verifier_type']} · {verification['result']} · {verification['created_at']}")
        self.plan_view.setPlainText('\n'.join(lines))
        self.buttons['approve_plan'].setEnabled(status == 'awaiting_plan_approval' and bool(plan))
        self.buttons['approve_step'].setEnabled(status == 'awaiting_step_approval')
        self.buttons['pause'].setEnabled(status in {'planned','ready','queued','running','verifying','awaiting_plan_approval','awaiting_step_approval','discovering'})
        self.buttons['resume'].setEnabled(status == 'paused')
        self.buttons['cancel'].setEnabled(status not in {'completed','cancelled','failed','rolled_back'})
        self._render_audit()

    def _render_audit(self, *_):
        task = self._selected()
        field, query = self.filter_field.currentText(), self.filter_text.text().casefold()
        lines = []
        for event in (task or {}).get('audit', []):
            safe = {key: event.get(key) for key in AUDIT_FIELDS if event.get(key) is not None}
            search = json.dumps(safe) if field == 'All fields' else str(safe.get(field, ''))
            if query in search.casefold():
                lines.append(' · '.join(f'{key}: {value}' for key, value in safe.items()))
        self.audit_view.setPlainText('\n'.join(lines))

    def _dispatch(self, action, **kwargs):
        if self._action_pending is not None and action not in {"stop_all", "stop_browser", "cancel", "pause"}:
            return
        if not self.action_callback:
            self.notice.setText('Task service is not connected.')
            return
        try:
            self._action_pending = self.action_callback(action, **kwargs)
            self.notice.setText('Updating task…')
        except Exception:
            self.notice.setText('Task action is unavailable.')

    def _submit(self):
        if self.request.text().strip():
            if self.mode.currentText() == "Coding":
                if not self.workspace.text().strip():
                    self.notice.setText("Choose the workspace first.")
                    return
                self._dispatch("submit_coding", text=self.request.text().strip(),
                               workspace=self.workspace.text().strip(), mode=self.coding_mode.currentData(), image_path=self.image_path.text().strip())
            elif self.mode.currentText() == "Browser":
                from urllib.parse import urlsplit
                url = self.browser_url.text().strip()
                domains = [value.strip().lower() for value in self.domains.text().split(",") if value.strip()]
                if not domains or urlsplit(url).scheme != "https":
                    self.notice.setText("Enter an HTTPS URL and the exact allowed domains first.")
                    return
                self._dispatch("submit_browser", text=self.request.text().strip(), url=url, domains=domains, browser_name=self.browser_choice.currentText())
            else:
                self._dispatch('submit', text=self.request.text().strip())

    def _mode_changed(self, mode):
        if not hasattr(self, "workspace"):
            return
        for widget in (self.workspace, self.choose_workspace, self.coding_mode):
            widget.setVisible(mode == "Coding")
        for widget in (self.browser_url, self.domains, self.browser_choice):
            widget.setVisible(mode == "Browser")
        self.image_path.setVisible(mode == 'Coding' and self.coding_mode.currentData() == 'debug')
        self.choose_image.setVisible(mode == 'Coding' and self.coding_mode.currentData() == 'debug')
        self.scope_note.setText({
            "Routine": "",
            "Coding": "Selected source and an explicitly chosen debug image go to your configured model after approval. Commands run locally with your account permissions, NOT in a sandbox. Review plans, file diffs and commands before allowing them.",
            "Browser": "Opens an isolated browser. Masked screenshots go to your configured Computer Use model. Each action requires approval; login, sending, purchases and downloads stop for takeover.",
        }[mode])

    def _choose_workspace(self):
        directory = QFileDialog.getExistingDirectory(self, "Choose coding workspace")
        if directory:
            self.workspace.setText(directory)

    def _choose_image(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Choose screenshot to share', '', 'Images (*.png *.jpg *.jpeg)')
        if path:
            self.image_path.setText(path)

    def _review_commands(self):
        task = self._selected()
        if not task or not task.get('coding'):
            return
        coding = task['coding']
        dialog = QDialog(self)
        dialog.setWindowTitle('Review local command plan')
        dialog.resize(700, 440)
        layout = QVBoxLayout(dialog)
        warning = QLabel('Runs locally with your account permissions. Workspace sets the working directory, not containment. Each command requires approval. Edit argv, purpose and timeout below.')
        warning.setWordWrap(True)
        layout.addWidget(warning)
        editor = QPlainTextEdit()
        editor.setPlainText(json.dumps((coding.get('inspection') or {}).get('commands', []), indent=2))
        layout.addWidget(editor)
        submit = QPushButton('Create command task for approval')
        layout.addWidget(submit)
        def create():
            try:
                commands = json.loads(editor.toPlainText())
                if not isinstance(commands, list) or not commands:
                    raise ValueError()
                self._dispatch('submit_commands', workspace=coding['workspace'], commands=commands)
                dialog.close()
            except (ValueError, TypeError):
                warning.setText('Enter a nonempty JSON list of commands with argv, purpose and timeout_seconds.')
        submit.clicked.connect(create)
        dialog.exec()

    def _code_control(self, action):
        task = self._selected()
        if task and task.get("coding"):
            coding = task["coding"]
            self._dispatch(action, session_id=coding["session_id"], diff_hash=coding["diff_hash"])

    def _stop_browser(self):
        task = self._selected()
        if task and task.get("browser_session_id"):
            self._dispatch("stop_browser", session_id=task["browser_session_id"])

    def _load_checkpoint(self):
        task = self._selected()
        if task and task.get("checkpoints"):
            self._dispatch("load_checkpoint", artifact_id=task["checkpoints"][0])

    def _control(self, name):
        task = self._selected()
        if not task:
            return
        if name == 'approve_step':
            pending = [a for a in task['approvals'] if a['decision'] == 'pending']
            if pending:
                self._show_approval(pending[-1])
            return
        kwargs = {'task_id': task['task_id']}
        if name == 'approve_plan':
            kwargs['plan_version'] = task['plan']['version']
        self._dispatch(name, **kwargs)

    def _show_approval(self, approval):
        dialog = QDialog(self, Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        dialog.setWindowTitle('Approve this exact action')
        dialog.resize(620, 430)
        layout = QVBoxLayout(dialog)
        details = QPlainTextEdit()
        details.setReadOnly(True)
        # Exact values are only shown here, in a trusted local window, never in audit.
        details.setPlainText(json.dumps({key: approval.get(key) for key in
            ('tool_name','target','arguments','risk','reason','plan_version','expires_at',
             'plan_summary','planned_files','diff','checks')}, indent=2, ensure_ascii=False))
        layout.addWidget(details)
        countdown = QLabel()
        layout.addWidget(countdown)
        row = QHBoxLayout()
        command = approval.get('tool_name') == 'coding_command'
        allow, deny = QPushButton('Allow once' if command else 'Approve once'), QPushButton('Deny')
        matching = QPushButton('Allow matching for this task/workspace')
        if command:
            warning = QLabel('Local execution is not sandboxed. Matching means exact command and arguments, only within this task/workspace; changed files require approval again.')
            warning.setWordWrap(True)
            layout.addWidget(warning)
            row.addWidget(matching)
        row.addWidget(deny)
        row.addWidget(allow)
        layout.addLayout(row)
        def finish(action, allow_matching=False):
            self._dispatch(action, approval_id=approval['approval_id'], **({'allow_matching': True} if allow_matching else {}))
            dialog.close()
        allow.clicked.connect(lambda: finish('approve_step'))
        matching.clicked.connect(lambda: finish('approve_step', True))
        deny.clicked.connect(lambda: finish('deny_step'))
        def expiry():
            try:
                remaining = (datetime.fromisoformat(approval['expires_at'].replace('Z', '+00:00')) - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError, KeyError):
                remaining = 0
            allow.setEnabled(remaining > 0)
            matching.setEnabled(remaining > 0)
            countdown.setText(f'Expires in {max(0, int(remaining))} seconds. Approval applies only to these values.')
        timer = QTimer(dialog)
        timer.timeout.connect(expiry)
        timer.start(1000)
        expiry()
        self._approval_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
