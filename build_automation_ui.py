import sys
import os
import json
import shutil
import subprocess
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar,
    QTextEdit, QMessageBox, QGroupBox
)
from PySide6.QtCore import Qt, QThread, Signal, QProcess

CONFIG_FILE = "build_ui_config.json"

class BuildWorker(QThread):
    progress_signal = Signal(int)
    log_signal = Signal(str)
    finished_signal = Signal(bool, str)

    def __init__(self, signtool, key_path, password, version):
        super().__init__()
        self.signtool = signtool
        self.key_path = key_path
        self.password = password
        self.version = version
        self._is_cancelled = False
        self.current_process = None

    def run(self):
        try:
            self.log_signal.emit("=== Pre-flight: Cleaning old dist folder ===")
            dist_path = Path("dist")
            if dist_path.exists():
                try:
                    shutil.rmtree(dist_path)
                    self.log_signal.emit("> Removed existing dist directory.")
                except Exception as e:
                    self.log_signal.emit(f"[WARNING] Could not remove dist: {e}")

            # Step 1: build_designer.bat
            self.progress_signal.emit(10)
            self.log_signal.emit("=== STEP 1: Building React Frontend ===")
            self._run_cmd(["cmd.exe", "/c", "build_designer.bat"])
            if self._is_cancelled: return
            
            # Step 2: build.bat <version>
            self.progress_signal.emit(40)
            self.log_signal.emit(f"=== STEP 2: Building MSI for Version {self.version} ===")
            self._run_cmd(["cmd.exe", "/c", "build.bat", self.version])
            if self._is_cancelled: return

            # Find the generated MSI
            msi_file = None
            dist_dir = Path("dist")
            if dist_dir.exists():
                for f in dist_dir.glob("*.msi"):
                    msi_file = f
                    break
            
            if not msi_file:
                raise Exception("Failed to find generated MSI file in the 'dist' directory.")

            self.log_signal.emit("=== Cleaning up MSI Build Artifacts ===")
            for folder_name in ["build", "ThreatPilot.egg-info"]:
                folder_path = Path(folder_name)
                if folder_path.exists() and folder_path.is_dir():
                    try:
                        shutil.rmtree(folder_path)
                        self.log_signal.emit(f"> Removed: {folder_name}")
                    except Exception as e:
                        self.log_signal.emit(f"[WARNING] Could not remove {folder_name}: {e}")

            # Step 3: signtool.exe
            self.progress_signal.emit(70)
            self.log_signal.emit("=== STEP 3: Code Signing MSI ===")
            # Command: signtool sign /f <key> /p <password> /fd SHA256 /t http://timestamp.digicert.com <msi>
            cmd_sign = [
                self.signtool, "sign", "/f", self.key_path, "/p", self.password,
                "/fd", "SHA256", "/t", "http://timestamp.digicert.com", str(msi_file)
            ]
            self._run_cmd(cmd_sign)
            if self._is_cancelled: return

            # Step 4: generate_hash.bat
            self.progress_signal.emit(90)
            self.log_signal.emit("=== STEP 4: Generating SHA256 Hash ===")
            self._run_cmd(["cmd.exe", "/c", "generate_hash.bat"])
            
            self.progress_signal.emit(100)
            self.log_signal.emit("=== BUILD WORKFLOW COMPLETED SUCCESSFULLY ===")
            self.finished_signal.emit(True, "Release successfully built, signed, and hashed!")
            
        except Exception as e:
            if not self._is_cancelled:
                self.log_signal.emit(f"\n[ERROR] {str(e)}")
                self.finished_signal.emit(False, str(e))
            else:
                self.finished_signal.emit(False, "Build cancelled by user.")

    def _run_cmd(self, cmd_list):
        self.log_signal.emit(f"> Executing: {' '.join(cmd_list)}")
        
        self.current_process = QProcess()
        self.current_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        
        # Start the process
        self.current_process.start(cmd_list[0], cmd_list[1:])
        if not self.current_process.waitForStarted():
            raise Exception(f"Failed to start command: {' '.join(cmd_list)}")
            
        # Close standard input so batch 'pause' commands automatically abort instead of freezing
        self.current_process.closeWriteChannel()

        # Poll every 100ms so we can instantly catch cancellations
        while self.current_process.state() == QProcess.ProcessState.Running:
            if self._is_cancelled:
                # Tree-kill the process to destroy cmd.exe and child node/python instances
                try:
                    import subprocess as sp
                    sp.Popen(["taskkill", "/F", "/T", "/PID", str(self.current_process.processId())], 
                             creationflags=sp.CREATE_NO_WINDOW)
                except:
                    pass
                self.current_process.kill()
                self.current_process.waitForFinished()
                raise Exception("Cancelled by user")

            if self.current_process.waitForReadyRead(100):
                out = self.current_process.readAll().data().decode('utf-8', errors='replace')
                for line in out.splitlines():
                    if line.strip():
                        self.log_signal.emit(line.strip())

        # Read any leftover output
        out = self.current_process.readAll().data().decode('utf-8', errors='replace')
        for line in out.splitlines():
            if line.strip():
                self.log_signal.emit(line.strip())
        
        if self._is_cancelled:
            raise Exception("Cancelled by user")
            
        if self.current_process.exitCode() != 0:
            raise Exception(f"Command failed with exit code {self.current_process.exitCode()}")

    def cancel(self):
        # Simply flip the flag. The worker thread will see it within 100ms.
        self._is_cancelled = True

class CleanWorker(QThread):
    log_signal = Signal(str)
    finished_signal = Signal()

    def run(self):
        try:
            self.log_signal.emit("=== RUNNING CLEAN.BAT ===")
            env = os.environ.copy()
            env["SKIP_VENV_CLEAN"] = "1"
            process = subprocess.Popen(
                ["cmd.exe", "/c", "clean.bat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                shell=False,
                env=env
            )
            for line in process.stdout:
                self.log_signal.emit(line.strip())
            process.wait()
            self.log_signal.emit("=== CLEANUP COMPLETED ===")
        except Exception as e:
            self.log_signal.emit(f"\n[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

class BuildAutomationUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatPilot Build Automation")
        self.resize(700, 600)
        self.worker = None

        self.setup_ui()
        self.load_config()

    def setup_ui(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f6f8fa; }
            QLabel { color: #24292f; font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; font-weight: 500; }
            QGroupBox { border: 1px solid #d0d7de; border-radius: 6px; margin-top: 10px; padding-top: 15px; background-color: #ffffff; color: #0969da; font-weight: bold; font-size: 14px; }
            QLineEdit { background-color: #ffffff; border: 1px solid #d0d7de; border-radius: 4px; padding: 6px; color: #24292f; }
            QLineEdit:focus { border: 1px solid #0969da; }
            QPushButton { background-color: #f3f4f6; border: 1px solid #d0d7de; border-radius: 4px; padding: 6px 12px; color: #24292f; font-weight: bold; }
            QPushButton:hover { background-color: #ebecf0; border-color: #8c959f; }
            QPushButton#btnStart { background-color: #2da44e; color: #ffffff; border: 1px solid #2c974b; font-size: 14px; padding: 8px 16px; }
            QPushButton#btnStart:hover { background-color: #2c974b; }
            QPushButton#btnStart:disabled { background-color: #e5e5e5; color: #8c959f; border: 1px solid #d0d7de; }
            QPushButton#btnCancel { background-color: #cf222e; color: #ffffff; border: 1px solid #a40e26; }
            QPushButton#btnCancel:hover { background-color: #a40e26; }
            QPushButton#btnCancel:disabled { background-color: #e5e5e5; color: #8c959f; border: 1px solid #d0d7de; }
            QPushButton#btnClean { background-color: #0969da; color: #ffffff; border: 1px solid #0969da; }
            QPushButton#btnClean:hover { background-color: #035cc5; }
            QPushButton#btnClean:disabled { background-color: #e5e5e5; color: #8c959f; border: 1px solid #d0d7de; }
            QProgressBar { border: 1px solid #d0d7de; border-radius: 4px; text-align: center; background-color: #ffffff; color: #24292f; font-weight: bold; }
            QProgressBar::chunk { background-color: #0969da; border-radius: 3px; }
            QTextEdit { background-color: #ffffff; border: 1px solid #d0d7de; border-radius: 4px; color: #1f2328; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; padding: 5px; }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("🚀 ThreatPilot Release Automation")
        title.setStyleSheet("font-size: 18px; color: #24292f; font-weight: bold; margin-bottom: 5px;")
        layout.addWidget(title)

        # Config Group
        cfg_group = QGroupBox("Configuration")
        cfg_layout = QVBoxLayout(cfg_group)
        
        # Signtool path
        s_layout = QHBoxLayout()
        s_layout.addWidget(QLabel("🛡️ Signtool.exe Path:"))
        self.signtool_input = QLineEdit()
        s_layout.addWidget(self.signtool_input)
        self.btn_browse_signtool = QPushButton("📂 Browse")
        self.btn_browse_signtool.clicked.connect(self.browse_signtool)
        s_layout.addWidget(self.btn_browse_signtool)
        cfg_layout.addLayout(s_layout)

        # Key path
        k_layout = QHBoxLayout()
        k_layout.addWidget(QLabel("🔑 Private Key (.pfx/.p12):"))
        self.key_input = QLineEdit()
        k_layout.addWidget(self.key_input)
        self.btn_browse_key = QPushButton("📂 Browse")
        self.btn_browse_key.clicked.connect(self.browse_key)
        k_layout.addWidget(self.btn_browse_key)
        cfg_layout.addLayout(k_layout)

        # Password
        p_layout = QHBoxLayout()
        p_layout.addWidget(QLabel("🔒 Private Key Password:"))
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        p_layout.addWidget(self.pwd_input)
        cfg_layout.addLayout(p_layout)

        # Version
        v_layout = QHBoxLayout()
        v_layout.addWidget(QLabel("🏷️ New Build Number:"))
        self.version_input = QLineEdit()
        self.version_input.setPlaceholderText("e.g. 2.1.0")
        v_layout.addWidget(self.version_input)
        cfg_layout.addLayout(v_layout)

        layout.addWidget(cfg_group)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Logs
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        # Actions
        a_layout = QHBoxLayout()
        
        self.btn_clean = QPushButton("🗑️ Clean Workspace")
        self.btn_clean.setObjectName("btnClean")
        self.btn_clean.clicked.connect(self.clean_workspace)
        a_layout.addWidget(self.btn_clean)

        self.btn_start = QPushButton("▶️ Start Build Process")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.clicked.connect(self.start_build)
        a_layout.addWidget(self.btn_start)
        
        self.btn_cancel = QPushButton("⏹️ Cancel")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.clicked.connect(self.cancel_build)
        self.btn_cancel.setEnabled(False)
        a_layout.addWidget(self.btn_cancel)
        
        layout.addLayout(a_layout)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    cfg = json.load(f)
                    self.signtool_input.setText(cfg.get("signtool_path", ""))
                    self.key_input.setText(cfg.get("key_path", ""))
                    self.version_input.setText(cfg.get("version", ""))
            except Exception:
                pass

    def save_config(self):
        cfg = {
            "signtool_path": self.signtool_input.text(),
            "key_path": self.key_input.text(),
            "version": self.version_input.text()
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass

    def browse_signtool(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select signtool.exe", "", "Executables (*.exe)")
        if path:
            self.signtool_input.setText(path)

    def browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Private Key", "", "Key Files (*.pfx *.p12);;All Files (*)")
        if path:
            self.key_input.setText(path)

    def append_log(self, text):
        self.log_area.append(text)
        scrollbar = self.log_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_progress(self, val):
        self.progress_bar.setValue(val)

    def start_build(self):
        signtool = self.signtool_input.text().strip()
        key = self.key_input.text().strip()
        pwd = self.pwd_input.text()
        ver = self.version_input.text().strip()

        if not signtool or not os.path.exists(signtool):
            QMessageBox.warning(self, "Error", "Invalid signtool path.")
            return
        if not key or not os.path.exists(key):
            QMessageBox.warning(self, "Error", "Invalid private key path.")
            return
        if not pwd:
            QMessageBox.warning(self, "Error", "Password is required for code signing.")
            return
        if not ver:
            QMessageBox.warning(self, "Error", "Build version is required.")
            return

        self.save_config()

        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_area.clear()

        self.worker = BuildWorker(signtool, key, pwd, ver)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.log_signal.connect(self.append_log)
        self.worker.finished_signal.connect(self.on_build_finished)
        self.worker.start()

    def cancel_build(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.append_log("\n[WARNING] Cancelling build process...")

    def clean_workspace(self):
        reply = QMessageBox.question(
            self, "Confirm Clean",
            "Are you sure you want to clean the workspace? This will run clean.bat.\n\nNote: The active virtual environment will NOT be deleted, protecting your current session.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.log_area.clear()
            self.btn_start.setEnabled(False)
            self.btn_clean.setEnabled(False)
            self.clean_worker = CleanWorker()
            self.clean_worker.log_signal.connect(self.append_log)
            self.clean_worker.finished_signal.connect(self.on_clean_finished)
            self.clean_worker.start()

    def on_clean_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_clean.setEnabled(True)

    def on_build_finished(self, success, message):
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        if success:
            QMessageBox.information(self, "Build Complete", message)
        else:
            QMessageBox.critical(self, "Build Failed", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BuildAutomationUI()
    window.show()
    sys.exit(app.exec())
