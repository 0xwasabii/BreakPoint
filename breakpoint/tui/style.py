"""Textual CSS for the Breakpoint TUI (kept in Python so it ships with the package)."""

CSS = """
$ink: #14110c;
$panel: #1d1913;
$line: #3a342a;
$paper: #f3efe6;
$mute: #8d8573;
$signal: #e4480b;
$ok: #5fa36d;

Screen { background: $ink; color: $paper; }

Header { background: $ink; color: $paper; }
Header .header--title, HeaderTitle { color: $paper; text-style: bold; }
Footer { background: $panel; }
Footer .footer-key--key { color: $signal; background: $panel; }

TabbedContent { height: 1fr; }
Tabs { background: $ink; }
Tab { color: $mute; padding: 0 2; }
Tab.-active { color: $signal; text-style: bold; }
Underline > .underline--bar { color: $signal; background: $line; }
TabPane { padding: 1 1 0 1; }

/* forms */
.form { width: 46; min-width: 40; border: round $line; padding: 0 1; background: $panel; }
.field { height: auto; margin-bottom: 1; }
.formbody { height: 1fr; }
.lbl { color: $mute; text-style: bold; height: 1; }
.hint { color: $mute; height: auto; }
Input { background: #2a251c; border: none; height: 1; padding: 0 1; }
Input:focus { background: #43301f; border: none; }
Input > .input--placeholder { color: #6e6757; }
Select { height: 1; }
SelectCurrent { background: #2a251c; border: none; height: 1; padding: 0 1; }
Select:focus > SelectCurrent { background: #43301f; border: none; }
TextArea { background: $ink; border: tall $line; height: 8; }
#sweep-targets { height: 6; }
TextArea:focus { border: tall $signal; }
Checkbox { background: $panel; border: none; height: 3; padding: 0; }
Checkbox:focus { background: $panel; }

Button { min-width: 12; height: 3; border: none; background: $line; color: $paper; }
Button:hover { background: #4b4437; }
Button.-primary { background: $signal; color: white; text-style: bold; }
Button.-primary:hover { background: #ff5a1f; }
Button.-error { background: #6b2a1a; }
.buttons { height: auto; margin-bottom: 1; }
.buttons Button { margin-right: 1; }

/* result panes */
.live { width: 1fr; margin-left: 1; }
.status { height: auto; padding: 0 1; color: $paper; border-left: thick $signal; margin-bottom: 1; }
ProgressBar { height: 1; padding: 0 1; margin-bottom: 1; }
Bar > .bar--bar { color: $signal; }
Bar > .bar--complete { color: $ok; }
PercentageStatus { color: $mute; }
DataTable { background: $panel; border: round $line; height: 1fr; }
DataTable > .datatable--header { background: $ink; color: $signal; text-style: bold; }
DataTable > .datatable--cursor { background: $signal 30%; }
RichLog { background: $panel; border: round $line; height: 1fr; padding: 0 1; }
.split { height: 1fr; }
.half { height: 1fr; }
.title { color: $signal; text-style: bold; margin-bottom: 1; }
.ok { color: $ok; }
.bad { color: $signal; }
.row { height: auto; margin-bottom: 1; }
.row Select { width: 20; margin-left: 1; }
.row Input { width: 1fr; }
.row Button { margin-left: 1; height: 1; min-width: 8; border: none; }
ModelsPane DataTable { height: 14; }
ModelsPane RichLog { height: 8; }
.role { width: 10; color: $mute; text-style: bold; }
"""
