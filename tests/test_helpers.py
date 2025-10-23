import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

qt_core = types.ModuleType("PyQt6.QtCore")
qt_core.Qt = types.SimpleNamespace(
    AlignmentFlag=types.SimpleNamespace(AlignCenter=0),
    Orientation=types.SimpleNamespace(Horizontal=0),
)


class DummyTimer:
    def __init__(self, *args, **kwargs):
        self.timeout = types.SimpleNamespace(connect=lambda *a, **k: None)

    def start(self, *args, **kwargs):
        pass


qt_core.QTimer = DummyTimer

qt_gui = types.ModuleType("PyQt6.QtGui")


class DummyFont:
    def __init__(self, *args, **kwargs):
        pass

    def setBold(self, *args, **kwargs):
        pass


qt_gui.QFont = DummyFont

qt_widgets = types.ModuleType("PyQt6.QtWidgets")


class _BaseWidget:
    def __init__(self, *args, **kwargs):
        self._value = 0

    def setFont(self, *args, **kwargs):
        pass

    def setContentsMargins(self, *args, **kwargs):
        pass

    def setSpacing(self, *args, **kwargs):
        pass

    def addWidget(self, *args, **kwargs):
        pass

    def addLayout(self, *args, **kwargs):
        pass

    def setMinimumWidth(self, *args, **kwargs):
        pass

    def setObjectName(self, *args, **kwargs):
        pass

    def addItems(self, *args, **kwargs):
        pass

    def clear(self, *args, **kwargs):
        pass

    def setEnabled(self, *args, **kwargs):
        pass

    def setWordWrap(self, *args, **kwargs):
        pass

    def resize(self, *args, **kwargs):
        pass

    def setRange(self, *args, **kwargs):
        pass

    def setValue(self, value):
        self._value = value

    def value(self):
        return self._value

    def currentText(self):
        return ""

    def exec(self):
        return None

    def text(self):
        return ""

    def setText(self, *args, **kwargs):
        pass

    def setStyleSheet(self, *args, **kwargs):
        pass

    def setWindowTitle(self, *args, **kwargs):
        pass

    def accept(self):
        pass

    def reject(self):
        pass


class DummyLayout(_BaseWidget):
    pass


class DummyButton(_BaseWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clicked = types.SimpleNamespace(connect=lambda *a, **k: None)


class DummyComboBox(_BaseWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._items = []

    def addItems(self, items):
        self._items.extend(items)

    def currentText(self):
        return self._items[0] if self._items else ""

    def clear(self):
        self._items.clear()

    def addItem(self, item):
        self._items.append(item)


class DummyListWidget(_BaseWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._items = []
        self.currentRowChanged = types.SimpleNamespace(connect=lambda *a, **k: None)

    def clear(self):
        self._items.clear()

    def addItem(self, item):
        self._items.append(item)

    def currentItem(self):
        return types.SimpleNamespace(text=lambda: self._items[0] if self._items else "")

    def currentRow(self):
        return 0 if self._items else -1


class DummyMessageBox:
    StandardButton = types.SimpleNamespace(Yes=1)

    @staticmethod
    def critical(*args, **kwargs):
        pass

    @staticmethod
    def warning(*args, **kwargs):
        pass

    @staticmethod
    def question(*args, **kwargs):
        return DummyMessageBox.StandardButton.Yes


qt_widgets.QApplication = type(
    "QApplication",
    (),
    {"instance": staticmethod(lambda: types.SimpleNamespace(quit=lambda: None))},
)
qt_widgets.QComboBox = DummyComboBox
qt_widgets.QCheckBox = _BaseWidget
qt_widgets.QDialog = _BaseWidget
qt_widgets.QGridLayout = DummyLayout
qt_widgets.QHBoxLayout = DummyLayout
qt_widgets.QLabel = _BaseWidget
qt_widgets.QLineEdit = _BaseWidget
qt_widgets.QListWidget = DummyListWidget
qt_widgets.QMessageBox = DummyMessageBox
qt_widgets.QPushButton = DummyButton
qt_widgets.QSlider = _BaseWidget
qt_widgets.QVBoxLayout = DummyLayout
qt_widgets.QWidget = _BaseWidget

sys.modules.setdefault("PyQt6", types.ModuleType("PyQt6"))
sys.modules["PyQt6"].__dict__.update({})
sys.modules["PyQt6.QtCore"] = qt_core
sys.modules["PyQt6.QtGui"] = qt_gui
sys.modules["PyQt6.QtWidgets"] = qt_widgets

import tech_toolbox  # noqa: E402

RealPath = Path


def test_build_terminal_command_selects_first_available(monkeypatch):
    monkeypatch.setattr(
        tech_toolbox,
        "TERMINAL_CANDIDATES",
        [("term-one", ["--opt"]), ("term-two", ["--other"])],
    )

    calls = []

    def fake_which(command_name: str):
        calls.append(command_name)
        if command_name == "term-two":
            return "/usr/bin/term-two"
        return None

    monkeypatch.setattr(tech_toolbox.shutil, "which", fake_which)

    result = tech_toolbox.build_terminal_command("echo hello")

    assert result == ["term-two", "--other", "echo hello"]
    assert calls == ["term-one", "term-two"]


def test_build_terminal_command_hold_open(monkeypatch):
    monkeypatch.setattr(
        tech_toolbox,
        "TERMINAL_CANDIDATES",
        [("term", ["-e", "bash", "-lc"])],
    )
    monkeypatch.setattr(tech_toolbox.shutil, "which", lambda _: "/usr/bin/term")

    result = tech_toolbox.build_terminal_command("ls", hold_open=True)

    assert result[-1].endswith("; echo 'Press Enter to close...'; read")


def test_build_terminal_command_no_terminal(monkeypatch):
    monkeypatch.setattr(tech_toolbox, "TERMINAL_CANDIDATES", [("term", ["-e"])])
    monkeypatch.setattr(tech_toolbox.shutil, "which", lambda _: None)

    with pytest.raises(FileNotFoundError):
        tech_toolbox.build_terminal_command("ls")


def test_build_tool_entry_rejects_non_string_program_command():
    toolbox = tech_toolbox.TechToolbox.__new__(tech_toolbox.TechToolbox)

    with pytest.raises(ValueError, match="missing 'command' for program tool"):
        toolbox._build_tool_entry({
            "label": "Example",
            "type": "program",
            "command": True,
        })


def test_build_tool_entry_rejects_non_string_terminal_command():
    toolbox = tech_toolbox.TechToolbox.__new__(tech_toolbox.TechToolbox)

    with pytest.raises(ValueError, match="missing 'command' for terminal tool"):
        toolbox._build_tool_entry({
            "label": "Example",
            "type": "terminal",
            "command": False,
        })


def test_list_physical_disks_parses_lsblk(monkeypatch):
    sample_output = """
    sda 931G disk
    sda1 100M part
    nvme0n1 476G disk
    """.strip()

    monkeypatch.setattr(
        tech_toolbox.subprocess,
        "check_output",
        lambda *args, **kwargs: sample_output,
    )

    disks = tech_toolbox.list_physical_disks()

    assert disks == [
        {"path": "/dev/sda", "display": "/dev/sda (931G)"},
        {"path": "/dev/nvme0n1", "display": "/dev/nvme0n1 (476G)"},
    ]


def test_list_physical_disks_fallback_sysfs(monkeypatch, tmp_path):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(tech_toolbox.subprocess, "check_output", raise_error)

    fake_root = tmp_path / "sys" / "block"
    fake_root.mkdir(parents=True)
    for name in ["sda", "loop0", "nvme0n1"]:
        (fake_root / name).mkdir()

    def fake_path(path_str: str):
        if path_str == "/sys/block":
            return RealPath(fake_root)
        return RealPath(path_str)

    monkeypatch.setattr(tech_toolbox, "Path", fake_path)

    disks = tech_toolbox.list_physical_disks()

    expected = [
        {"path": "/dev/sda", "display": "/dev/sda"},
        {"path": "/dev/nvme0n1", "display": "/dev/nvme0n1"},
    ]

    assert sorted(disks, key=lambda item: item["path"]) == sorted(
        expected, key=lambda item: item["path"]
    )


def test_get_sensors_data_parses_output(monkeypatch):
    sensors_output = """
    fan1:        1200 RPM
    CPU Temp:    +45.0°C
    chassis fan: 900 rpm
    """.strip()

    monkeypatch.setattr(
        tech_toolbox.subprocess, "check_output", lambda *args, **kwargs: sensors_output
    )

    data = tech_toolbox.get_sensors_data()

    assert data["Fan_Speed"] == {"fan1": "1200", "chassis fan": "900"}


def test_get_sensors_data_handles_error(monkeypatch):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(tech_toolbox.subprocess, "check_output", raise_error)

    data = tech_toolbox.get_sensors_data()

    assert data == {"Fan_Speed": {}}


def test_launch_ddrescue_gui_prepares_paths(monkeypatch):
    toolbox = tech_toolbox.TechToolbox.__new__(tech_toolbox.TechToolbox)

    recorded_errors: list[tuple[str, str]] = []
    recorded_commands: list[str] = []

    toolbox.show_warning = lambda *args, **kwargs: None

    def fake_show_error(title: str, message: str) -> None:
        recorded_errors.append((title, message))

    toolbox.show_error = fake_show_error
    toolbox.run_terminal_task = lambda command: recorded_commands.append(command)

    dialog_instances = []

    class RecordingDialog:
        def __init__(self, *args, **kwargs):
            self.accept_called = False
            dialog_instances.append(self)

        def setWindowTitle(self, *args, **kwargs):
            pass

        def exec(self):
            return None

        def accept(self):
            self.accept_called = True

    monkeypatch.setattr(tech_toolbox, "QDialog", RecordingDialog)

    line_edits = []

    class RecordingLineEdit:
        def __init__(self, *args, **kwargs):
            self._text = ""
            line_edits.append(self)

        def text(self):
            return self._text

        def setText(self, value):
            self._text = value

    monkeypatch.setattr(tech_toolbox, "QLineEdit", RecordingLineEdit)

    buttons = []

    class RecordingButton:
        def __init__(self, *args, **kwargs):
            self._callback = None
            self.clicked = types.SimpleNamespace(connect=self._connect)
            buttons.append(self)

        def _connect(self, callback):
            self._callback = callback

        def trigger(self):
            if self._callback:
                self._callback()

    monkeypatch.setattr(tech_toolbox, "QPushButton", RecordingButton)

    operations = []

    class FakeParent:
        def __init__(self, label: str):
            self.label = label

        def mkdir(self, parents: bool = False, exist_ok: bool = False):
            operations.append(("mkdir", self.label, parents, exist_ok))

    class FakePath:
        def __init__(self, raw: str):
            self.raw = raw

        @property
        def parent(self):
            return FakeParent(f"parent({self.raw})")

        def touch(self, exist_ok: bool = False):
            operations.append(("touch", self.raw, exist_ok))

    def fake_path_factory(value):
        if isinstance(value, FakePath):
            return value
        return FakePath(str(value))

    monkeypatch.setattr(tech_toolbox, "Path", fake_path_factory)

    toolbox.launch_ddrescue_gui()

    assert len(line_edits) == 3

    src_entry, dest_entry, log_entry = line_edits
    src_entry.setText("/dev/sdb")
    dest_entry.setText("/tmp/recovery.img")
    log_entry.setText("/tmp/recovery.log")

    buttons[-1].trigger()

    assert operations == [
        ("mkdir", "parent(/tmp/recovery.img)", True, True),
        ("touch", "/tmp/recovery.img", True),
        ("mkdir", "parent(/tmp/recovery.log)", True, True),
        ("touch", "/tmp/recovery.log", True),
    ]

    assert recorded_commands == [
        "sudo ddrescue /dev/sdb /tmp/recovery.img /tmp/recovery.log"
    ]

    assert recorded_errors == []
    assert dialog_instances[-1].accept_called


def test_secure_wipe_displays_mount_points_with_spaces(monkeypatch):
    sample_output = """NAME   SIZE TYPE MOUNTPOINT
sda    931G disk /mnt/data
sdb    476G disk /media/My Drive
""".strip()

    monkeypatch.setattr(
        tech_toolbox.subprocess,
        "check_output",
        lambda *args, **kwargs: sample_output,
    )

    toolbox = tech_toolbox.TechToolbox.__new__(tech_toolbox.TechToolbox)
    toolbox._get_tool_dependencies = lambda *args, **kwargs: []
    toolbox.ensure_commands_available = lambda *args, **kwargs: True
    toolbox.show_error = lambda *args, **kwargs: None
    toolbox.show_warning = lambda *args, **kwargs: None
    toolbox.run_terminal_task = lambda *args, **kwargs: None

    created_lists = []

    class RecordingListWidget(DummyListWidget):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created_lists.append(self)

    monkeypatch.setattr(tech_toolbox, "QListWidget", RecordingListWidget)

    toolbox.secure_wipe()

    assert created_lists, "Drive list widget was not created"
    assert (
        "sdb (476G) – mounted at /media/My Drive" in created_lists[0]._items
    )
