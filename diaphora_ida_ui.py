"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015-2026 Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os

import idc
import idautils
import ida_pro
import ida_registry

import diaphora_config as config

if ida_pro.IDA_SDK_VERSION >= 920:
  from PySide6 import QtWidgets
else:
  from PyQt5 import QtWidgets

#-------------------------------------------------------------------------------
# IDA registry keys to load/save settings
REGISTRY_SUBKEY = "Diaphora"
REGISTRY_RECENT_DIFF_DATABASES = "DiaphoraRecentDiffDatabases"

# Maximum number of SQLite databases remembered
MAX_RECENT_DIFF_DATABASES = 10

# Diffing options Diaphora will load/save
REMEMBERED_DIFFING_OPTIONS = [
  "unreliable",
  "relax",
  "experimental",
  "ignore_sub_names",
  "ignore_all_names",
  "use_trained_model",
]

SQLITE_FILE_FILTER = "SQLite database (*.sqlite *.db);;All files (*)"
PYTHON_FILE_FILTER = "Python scripts (*.py);;All files (*)"

#-------------------------------------------------------------------------------
def get_ida_main_window():
  for widget in QtWidgets.QApplication.topLevelWidgets():
    if isinstance(widget, QtWidgets.QMainWindow):
      return widget
  return None

#-------------------------------------------------------------------------------
def is_ida_file(filename):
  filename = filename.lower()
  return filename.endswith((".idb", ".i64", ".til", ".id0", ".id1", ".nam"))

#-------------------------------------------------------------------------------
def get_paths_error(file_out, file_in):
  if file_out == "" or len(file_out) < 5:
    return "No output database selected or invalid filename. Please select a SQLite database file."
  elif file_out == file_in:
    return "Both databases are the same file!"
  elif is_ida_file(file_in) or is_ida_file(file_out):
    return "One of the selected databases is an IDA file. Please select only SQLite database files."
  return None

#-------------------------------------------------------------------------------
class CDiaphoraSetupDialog(QtWidgets.QDialog):
  def __init__(self, total_functions, has_decompiler, make_default_options):
    QtWidgets.QDialog.__init__(self, get_ida_main_window())
    self.setWindowTitle("Diaphora")
    self.setMinimumWidth(720)

    self.total_functions = total_functions
    self.has_decompiler = has_decompiler
    self.make_default_options = make_default_options
    self.opts = None

    layout = QtWidgets.QVBoxLayout(self)
    intro = QtWidgets.QLabel(
      "Export the current IDA database to SQLite format and, optionally, diff "
      "it against another SQLite database exported by Diaphora. Leave "
      "<i>Diff against</i> empty if you are exporting the first database."
    )
    intro.setWordWrap(True)
    layout.addWidget(intro)
    layout.addWidget(self.build_databases_group())

    tabs = QtWidgets.QTabWidget()
    tabs.addTab(self.build_export_tab(), "Export")
    self.diffing_tab = self.build_diffing_tab()
    tabs.addTab(self.diffing_tab, "Diffing")
    tabs.addTab(self.build_advanced_tab(), "Advanced")
    layout.addWidget(tabs)

    self.buttons = QtWidgets.QDialogButtonBox(
      QtWidgets.QDialogButtonBox.Ok
      | QtWidgets.QDialogButtonBox.Cancel
      | QtWidgets.QDialogButtonBox.RestoreDefaults
    )
    self.buttons.accepted.connect(self.accept)
    self.buttons.rejected.connect(self.reject)
    restore_button = self.buttons.button(QtWidgets.QDialogButtonBox.RestoreDefaults)
    msg = "Reset all the export and diffing options to the values in diaphora_config.py"
    restore_button.setToolTip(msg)
    restore_button.clicked.connect(self.restore_defaults)
    layout.addWidget(self.buttons)

    self.connect_signals()

  def get_start_directory(self, path):
    if path == "":
      return os.path.dirname(idc.get_idb_path())
    return path

  def browse_file_out(self):
    start = self.get_start_directory(self.file_out.text().strip())
    path, _ = QtWidgets.QFileDialog.getSaveFileName(
      self, "Export IDA database to SQLite", start, SQLITE_FILE_FILTER
    )
    if path != "":
      self.file_out.setText(path)

  def browse_file_in(self):
    start = self.get_start_directory(self.file_in.currentText().strip())
    path, _ = QtWidgets.QFileDialog.getOpenFileName(
      self, "SQLite database to diff against", start, SQLITE_FILE_FILTER
    )
    if path != "":
      self.file_in.setEditText(path)

  def browse_project_script(self):
    start = self.get_start_directory(self.project_script.text().strip())
    path, _ = QtWidgets.QFileDialog.getOpenFileName(
      self, "Project specific Python script", start, PYTHON_FILE_FILTER
    )
    if path != "":
      self.project_script.setText(path)

  def add_file_row(self, form, label, widget, button):
    row = QtWidgets.QHBoxLayout()
    row.addWidget(widget, 1)
    row.addWidget(button)
    form.addRow(label, row)

  def build_databases_group(self):
    group = QtWidgets.QGroupBox("SQLite databases")
    form = QtWidgets.QFormLayout(group)

    self.file_out = QtWidgets.QLineEdit()
    self.file_out.setToolTip(
      "Select a file to export the current IDA database to SQLite format"
    )
    button = QtWidgets.QPushButton("Browse...")
    button.clicked.connect(self.browse_file_out)
    self.add_file_row(form, "Export to:", self.file_out, button)

    self.file_in = QtWidgets.QComboBox()
    self.file_in.setEditable(True)
    self.file_in.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
    self.file_in.lineEdit().setPlaceholderText("Leave empty to only export")
    self.file_in.setToolTip("Select the SQLite database to diff against.")
    for path in ida_registry.reg_read_strlist(REGISTRY_RECENT_DIFF_DATABASES):
      self.file_in.addItem(path)
    self.file_in.setEditText("")
    button = QtWidgets.QPushButton("Browse...")
    button.clicked.connect(self.browse_file_in)
    self.add_file_row(form, "Diff against:", self.file_in, button)

    self.status_label = QtWidgets.QLabel()
    self.status_label.setWordWrap(True)
    form.addRow(self.status_label)
    return group

  def add_checkbox(self, layout, text, tooltip):
    checkbox = QtWidgets.QCheckBox(text)
    checkbox.setToolTip(tooltip)
    layout.addWidget(checkbox)
    return checkbox

  def add_note(self, layout, text):
    note = QtWidgets.QLabel(text)
    note.setWordWrap(True)
    note.setContentsMargins(24, 0, 0, 4)
    font = note.font()
    font.setItalic(True)
    note.setFont(font)
    layout.addWidget(note)
    return note

  def build_export_tab(self):
    tab = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(tab)

    self.use_decompiler = self.add_checkbox(
      layout,
      "Use the decompiler if available",
      "Export the pseudo-code and other decompiler based information",
    )
    if not self.has_decompiler:
      self.add_note(layout, "The decompiler is not available.")

    self.export_microcode = self.add_checkbox(
      layout,
      "Export microcode instructions and basic blocks",
      "Use this option to enable or disable exporting microcode",
    )
    if self.total_functions > config.MIN_FUNCTIONS_TO_CONSIDER_MEDIUM:
      msg = "Disabled by default because the database has %d functions (more "
      msg += "than %d). Microcode slows down the export process and might cause "
      msg += "false positives."
      msg %= (self.total_functions, config.MIN_FUNCTIONS_TO_CONSIDER_MEDIUM - 1)
      self.add_note(layout, msg)

    self.exclude_library_thunk = self.add_checkbox(
      layout,
      "Do not export library and thunk functions",
      "Library and thunk functions will not be exported",
    )
    self.non_ida_subs = self.add_checkbox(
      layout,
      "Export only non-IDA generated functions",
      "Enable if you want neither sub_* functions nor library functions to be exported",
    )

    self.func_summaries_only = self.add_checkbox(
      layout,
      "Do not export instructions and basic blocks",
      "Export only function summaries, not all instructions. Showing differences "
      "in a graph between functions will not be available.",
    )
    if self.total_functions > config.MIN_FUNCTIONS_TO_CONSIDER_HUGE:
      msg = "Enabled by default because the database has %d functions (more "
      msg += "than %d). 'Diff assembly in a graph' will not be available."
      msg %= (self.total_functions, config.MIN_FUNCTIONS_TO_CONSIDER_HUGE)
      self.add_note(layout, msg)

    layout.addWidget(self.build_address_range_group())
    layout.addStretch(1)
    return tab

  def build_address_range_group(self):
    group = QtWidgets.QGroupBox("Export filter limits")
    form = QtWidgets.QFormLayout(group)

    self.segments = QtWidgets.QComboBox()
    self.segments.setToolTip("Fill the address range with a whole segment")
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    self.segment_ranges = [(min_ea, max_ea)]
    self.segments.addItem("Whole program")
    for start in idautils.Segments():
      end = idc.get_segm_end(start)
      name = idc.get_segm_name(start)
      self.segment_ranges.append((start, end))
      self.segments.addItem("%s [0x%x - 0x%x]" % (name, start, end))
    form.addRow("Segment:", self.segments)

    self.min_ea = QtWidgets.QLineEdit()
    self.min_ea.setToolTip("Minimum address to find functions to export")
    self.max_ea = QtWidgets.QLineEdit()
    self.max_ea.setToolTip("Maximum address to find functions to export")

    row = QtWidgets.QHBoxLayout()
    row.addWidget(self.min_ea, 1)
    row.addWidget(QtWidgets.QLabel("To:"))
    row.addWidget(self.max_ea, 1)
    form.addRow("From:", row)
    return group

  def build_diffing_tab(self):
    tab = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(tab)

    self.diffing_disabled_note = QtWidgets.QLabel(
      "Select a database in <i>Diff against</i> to change the diffing options."
    )
    self.diffing_disabled_note.setWordWrap(True)
    layout.addWidget(self.diffing_disabled_note)

    self.diffing_options = QtWidgets.QWidget()
    options_layout = QtWidgets.QVBoxLayout(self.diffing_options)
    options_layout.setContentsMargins(0, 0, 0, 0)

    self.unreliable = self.add_checkbox(
      options_layout,
      "Use probably unreliable methods",
      "Run heuristics that might find more matches but also cause false positives",
    )

    msg = "Recommended to disable with databases with more than %d functions"
    msg %= (config.MIN_FUNCTIONS_TO_DISABLE_SLOW - 1)
    self.slow = self.add_checkbox(options_layout, "Use slow heuristics", msg)
    if self.total_functions >= config.MIN_FUNCTIONS_TO_DISABLE_SLOW:
      msg = "Disabled by default because the database has %d functions (more than %d)."
      msg %= (self.total_functions, config.MIN_FUNCTIONS_TO_DISABLE_SLOW - 1)
      self.add_note(options_layout, msg)

    self.relax = self.add_checkbox(
      options_layout,
      "Relaxed calculations of differences ratios",
      "Enable this option if you aren't interested in small changes",
    )
    self.relax_note = self.add_note(
      options_layout,
      "Many small modifications to functions will be ignored and more functions "
      "will be matched with higher ratios. Good if you're only interested in new "
      "functionality; disable it for patch diffing if you're interested in small "
      "modifications (like buffer sizes).",
    )

    self.experimental = self.add_checkbox(
      options_layout,
      "Use speed ups",
      "Use tricks to speed ups some of the most common diffing tasks",
    )
    self.ignore_small_functions = self.add_checkbox(
      options_layout,
      "Ignore small functions",
      "Enable this option to ignore thunk functions, nullsubs, etc...",
    )
    self.ignore_sub_names = self.add_checkbox(
      options_layout,
      "Ignore automatically generated names",
      "Enable this option to ignore sub_* names for the 'Same name' heuristic.",
    )
    self.ignore_all_names = self.add_checkbox(
      options_layout,
      "Ignore all function names",
      "Enable this option to ignore all function names for the 'Same name' "
      "heuristic. It includes ignoring automatically generated names.",
    )

    self.use_trained_model = self.add_checkbox(
      options_layout,
      "Use an already trained model",
      "Enable this option to use the Machine Learning engine with an already "
      "trained model specified in diaphora_config.py!ML_TRAINED_MODEL.",
    )
    self.has_trained_model = os.path.exists(config.ML_TRAINED_MODEL)
    if not self.has_trained_model:
      self.add_note(
        options_layout,
        f"The trained model was not found: {config.ML_TRAINED_MODEL}",
      )

    layout.addWidget(self.diffing_options)
    layout.addStretch(1)
    return tab

  def build_advanced_tab(self):
    tab = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(tab)
    group = QtWidgets.QGroupBox("Project specific rules")
    form = QtWidgets.QFormLayout(group)

    self.project_script = QtWidgets.QLineEdit()
    self.project_script.setToolTip(
      "Select the project specific Python script rules. It is used for both "
      "exporting and diffing."
    )
    button = QtWidgets.QPushButton("Browse...")
    button.clicked.connect(self.browse_project_script)
    self.add_file_row(form, "Python script:", self.project_script, button)

    layout.addWidget(group)
    layout.addStretch(1)
    return tab

  def connect_signals(self):
    self.file_out.textChanged.connect(self.validate)
    self.file_in.editTextChanged.connect(self.validate)
    self.min_ea.textChanged.connect(self.validate)
    self.max_ea.textChanged.connect(self.validate)
    self.segments.activated.connect(self.segment_selected)

    self.func_summaries_only.toggled.connect(self.update_dependent_options)
    self.ignore_all_names.toggled.connect(self.update_dependent_options)
    self.relax.toggled.connect(self.update_dependent_options)

    self.use_decompiler.setEnabled(self.has_decompiler)
    self.use_trained_model.setEnabled(self.has_trained_model)

  def update_dependent_options(self):
    # Microcode is not exported when only function summaries are exported
    self.export_microcode.setEnabled(not self.func_summaries_only.isChecked())
    # Ignoring all the names already ignores the automatically generated ones
    self.ignore_sub_names.setEnabled(not self.ignore_all_names.isChecked())
    self.relax_note.setVisible(self.relax.isChecked())

  def segment_selected(self, index):
    start, end = self.segment_ranges[index]
    self.min_ea.setText("0x%x" % start)
    self.max_ea.setText("0x%x" % end)

  def get_address(self, edit):
    text = edit.text().strip()
    if text == "":
      return None
    try:
      return int(text, 16)
    except ValueError:
      return None

  def validate(self):
    file_out = self.file_out.text().strip()
    file_in = self.file_in.currentText().strip()

    error = get_paths_error(file_out, file_in)
    if error is None:
      min_ea = self.get_address(self.min_ea)
      max_ea = self.get_address(self.max_ea)
      if min_ea is None or max_ea is None:
        error = "Enter both addresses of the export filter limits."
      elif min_ea > max_ea:
        error = "The 'From' address is bigger than the 'To' address."

    ok_button = self.buttons.button(QtWidgets.QDialogButtonBox.Ok)
    ok_button.setEnabled(error is None)
    if file_in != "":
      ok_button.setText("Export and diff")
    else:
      ok_button.setText("Export")

    self.diffing_options.setEnabled(file_in != "")
    self.diffing_disabled_note.setVisible(file_in == "")

    if error is not None:
      self.status_label.setText(f"<font color='#e04040'>{error}</font>")
    elif file_in != "":
      self.status_label.setText(
        "The current database will be exported and diffed against the selected one."
      )
    else:
      self.status_label.setText("The current database will only be exported.")

  def apply_saved_settings(self, explicit_options):
    for name in REMEMBERED_DIFFING_OPTIONS:
      if name not in explicit_options:
        checkbox = getattr(self, name)
        checkbox.setChecked(
          ida_registry.reg_read_bool(name, checkbox.isChecked(), REGISTRY_SUBKEY)
        )

  def save_settings(self):
    file_in = self.file_in.currentText().strip()
    if file_in != "":
      ida_registry.reg_update_filestrlist(
        REGISTRY_RECENT_DIFF_DATABASES, file_in, MAX_RECENT_DIFF_DATABASES
      )

      # Only remember diffing options when they are actually used
      for name in REMEMBERED_DIFFING_OPTIONS:
        checkbox = getattr(self, name)
        ida_registry.reg_write_bool(name, checkbox.isChecked(), REGISTRY_SUBKEY)

  def restore_defaults(self):
    defaults = self.make_default_options()
    self.set_check_options(defaults)
    self.min_ea.setText("0x%x" % defaults.min_ea)
    self.max_ea.setText("0x%x" % defaults.max_ea)
    self.segments.setCurrentIndex(0)

  def set_check_options(self, opts):
    self.use_decompiler.setChecked(bool(opts.use_decompiler))
    self.exclude_library_thunk.setChecked(bool(opts.exclude_library_thunk))
    self.unreliable.setChecked(bool(opts.unreliable))
    self.slow.setChecked(bool(opts.slow))
    self.use_trained_model.setChecked(bool(opts.use_trained_model))
    self.relax.setChecked(bool(opts.relax))
    self.experimental.setChecked(bool(opts.experimental))
    self.non_ida_subs.setChecked(not opts.ida_subs)
    self.ignore_sub_names.setChecked(bool(opts.ignore_sub_names))
    self.ignore_all_names.setChecked(bool(opts.ignore_all_names))
    self.ignore_small_functions.setChecked(bool(opts.ignore_small_functions))
    self.func_summaries_only.setChecked(bool(opts.func_summaries_only))
    self.export_microcode.setChecked(bool(opts.export_microcode))
    self.update_dependent_options()

  def set_options(self, opts, explicit_options=()):
    self.opts = opts
    if opts.file_out is not None:
      self.file_out.setText(opts.file_out)
    if opts.file_in is not None:
      self.file_in.setEditText(opts.file_in)
    if opts.project_script is not None:
      self.project_script.setText(opts.project_script)
    self.min_ea.setText("0x%x" % opts.min_ea)
    self.max_ea.setText("0x%x" % opts.max_ea)
    self.set_check_options(opts)
    self.apply_saved_settings(explicit_options)
    self.validate()

  def get_options(self):
    opts = self.opts
    opts.file_out = self.file_out.text().strip()
    opts.file_in = self.file_in.currentText().strip()
    # Unavailable options are returned as off
    opts.use_decompiler = self.use_decompiler.isEnabled() and self.use_decompiler.isChecked()
    opts.exclude_library_thunk = self.exclude_library_thunk.isChecked()
    opts.unreliable = self.unreliable.isChecked()
    opts.slow = self.slow.isChecked()
    opts.use_trained_model = self.use_trained_model.isEnabled() and self.use_trained_model.isChecked()
    opts.relax = self.relax.isChecked()
    opts.experimental = self.experimental.isChecked()
    opts.min_ea = self.get_address(self.min_ea)
    opts.max_ea = self.get_address(self.max_ea)
    opts.ida_subs = not self.non_ida_subs.isChecked()
    opts.ignore_sub_names = self.ignore_sub_names.isChecked() or self.ignore_all_names.isChecked()
    opts.ignore_all_names = self.ignore_all_names.isChecked()
    opts.ignore_small_functions = self.ignore_small_functions.isChecked()
    opts.func_summaries_only = self.func_summaries_only.isChecked()
    opts.export_microcode = self.export_microcode.isEnabled() and self.export_microcode.isChecked()

    project_script = self.project_script.text().strip()
    opts.project_script = None
    if project_script != "":
      opts.project_script = project_script
    return opts

  def Execute(self):
    if ida_pro.IDA_SDK_VERSION >= 920:
      ret = self.exec()
    else:
      ret = self.exec_()

    accepted = ret == QtWidgets.QDialog.Accepted
    if accepted:
      self.save_settings()
    return accepted
