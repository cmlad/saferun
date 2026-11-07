//! "SR" menu bar item for the approval broker.
//!
//! A long-running `osascript` JXA helper owns the status item. Its stdin is a
//! pipe held by the broker: when the broker exits, the helper sees EOF and
//! quits. When the helper exits (e.g. via its Quit item), the broker should
//! exit too; callers wait on the returned child for that.

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Status item title shown in the menu bar.
pub const TITLE: &str = "SR";

/// JXA program for the status item helper.
pub fn build_program(log_path: &Path) -> Result<String, String> {
    let log_path_json = serde_json::to_string(&log_path.to_string_lossy())
        .map_err(|_| "cannot encode log path".to_string())?;
    let title_json = serde_json::to_string(TITLE).expect("static title");
    Ok(format!(
        r#"ObjC.import("Cocoa");
const logPath = {log_path_json};
const app = $.NSApplication.sharedApplication;
app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
ObjC.registerSubclass({{
    name: "SaferunStatusController",
    methods: {{
        "copyLogPath:": {{
            types: ["void", ["id"]],
            implementation: function(sender) {{
                const pasteboard = $.NSPasteboard.generalPasteboard;
                pasteboard.clearContents;
                pasteboard.setStringForType($(logPath), $.NSPasteboardTypeString);
            }}
        }},
        "quit:": {{
            types: ["void", ["id"]],
            implementation: function(sender) {{
                app.terminate(null);
            }}
        }},
        "stdinRead:": {{
            types: ["void", ["id"]],
            implementation: function(notification) {{
                const data = notification.userInfo.objectForKey(
                    $.NSFileHandleNotificationDataItem
                );
                if (data.isNil() || Number(data.length) === 0) {{
                    app.terminate(null);
                }} else {{
                    notification.object.readInBackgroundAndNotify;
                }}
            }}
        }}
    }}
}});
const controller = $.SaferunStatusController.alloc.init;
// -1 is NSVariableStatusItemLength.
const statusItem = $.NSStatusBar.systemStatusBar.statusItemWithLength(-1);
statusItem.button.setTitle({title_json});
statusItem.button.setToolTip("saferun approval");
const menu = $.NSMenu.alloc.init;
function addItem(title, action) {{
    const item = $.NSMenuItem.alloc.initWithTitleActionKeyEquivalent(title, action, "");
    item.setTarget(controller);
    menu.addItem(item);
}}
addItem("Copy log file path", "copyLogPath:");
menu.addItem($.NSMenuItem.separatorItem);
addItem("Quit saferun approval", "quit:");
statusItem.setMenu(menu);
const stdin = $.NSFileHandle.fileHandleWithStandardInput;
$.NSNotificationCenter.defaultCenter.addObserverSelectorNameObject(
    controller,
    "stdinRead:",
    $.NSFileHandleReadCompletionNotification,
    stdin
);
stdin.readInBackgroundAndNotify;
app.run;
"#
    ))
}

/// Start the status item helper. Keep the returned child (and its stdin) alive
/// for as long as the item should be shown.
pub fn spawn(log_path: &Path) -> Result<Child, String> {
    let program = build_program(log_path)?;
    Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript", "-e", &program])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start status item: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_embeds_title_menu_and_quoted_log_path() {
        let program = build_program(Path::new("/Users/a \"b\"/approval.log")).expect("program");
        assert!(program.contains(r#"const logPath = "/Users/a \"b\"/approval.log";"#));
        assert!(program.contains(r#"statusItem.button.setTitle("SR");"#));
        assert!(program.contains(r#"addItem("Copy log file path", "copyLogPath:");"#));
    }
}
