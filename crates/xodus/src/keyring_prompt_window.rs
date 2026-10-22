//! Route only the provider's parented password prompt to the caller in Gamescope.
//! No keyboard hooks, input injection, screenshots or password handling.
use std::{ptr, ffi::{c_int, c_ulong}};
use x11_dl::xlib;
use std::io::Read;

fn reaper_app(arguments: &[u8]) -> Option<c_ulong> {
    let mut launch = false;
    for argument in arguments.split(|&byte| byte == 0) {
        if argument == b"--" { break; }
        if argument == b"SteamLaunch" { launch = true; continue; }
        if launch {
            if let Some(value) = argument.strip_prefix(b"AppId=") {
                let app = std::str::from_utf8(value).ok()?.parse::<u32>().ok()?;
                return (app != 0).then_some(app as c_ulong);
            }
        }
    }
    None
}
fn bounded_proc(file: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(file).ok()?.take(8193).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 8192).then_some(bytes)
}
fn parent_app(mut pid: u32) -> Option<c_ulong> {
    // Steam's reaper, not arbitrary inherited environment variables, identifies
    // the shortcut. Secondary Gamescope X servers omit the root app table.
    for _ in 0..32 {
        let stat = String::from_utf8(bounded_proc(&format!("/proc/{pid}/stat"))?).ok()?;
        let end = stat.rfind(')')?;
        if stat.get(stat.find('(')? + 1..end)? == "reaper" {
            if let Some(app) = reaper_app(&bounded_proc(&format!("/proc/{pid}/cmdline"))?) { return Some(app); }
        }
        let next = stat[end + 1..].split_whitespace().nth(1)?.parse::<u32>().ok()?;
        if next == 0 || next == pid { break; }
        pid = next;
    }
    None
}

fn app_for_parent(parent: c_ulong, pid: u32, table: &[c_ulong]) -> Option<c_ulong> {
    table.chunks_exact(3).find_map(|entry| {
        (entry[0] == parent && entry[2] == pid as c_ulong && entry[1] != 0 && entry[1] <= u32::MAX as c_ulong)
            .then_some(entry[1])
    })
}
fn belongs_to_prompt(pid: Option<c_ulong>, transient: c_ulong, owner: u32, parent: c_ulong) -> bool {
    pid == Some(owner as c_ulong) && transient == parent && parent != 0
}

pub(super) struct PromptWindows {
    x: xlib::Xlib,
    display: *mut xlib::Display,
    root: c_ulong,
    parent: c_ulong,
    owner: u32,
    app: c_ulong,
    changed: Vec<(c_ulong, Option<c_ulong>)>,
}
unsafe extern "C" fn ignore_error(_: *mut xlib::Display, _: *mut xlib::XErrorEvent) -> c_int { 0 }
impl PromptWindows {
    pub(super) fn new(parent: c_ulong, owner: u32, gamescope: bool) -> Option<Self> {
        let x = xlib::Xlib::open().ok()?;
        // This CLI route runs before any GUI initialization. Windows can vanish
        // between metadata reads; treat their X errors as missing metadata.
        unsafe { (x.XSetErrorHandler)(Some(ignore_error)); }
        let display = unsafe { (x.XOpenDisplay)(ptr::null()) };
        if display.is_null() { return None; }
        let root = unsafe { (x.XDefaultRootWindow)(display) };
        let mut result = Self { x, display, root, parent, owner, app: 0, changed: Vec::new() };
        let pid = unsafe { libc::getppid() } as u32;
        if result.values(parent, c"_NET_WM_PID", 1)?.first().copied() != Some(pid as c_ulong) { return None; }
        if gamescope {
            result.app = result.values(root, c"GAMESCOPE_FOCUSABLE_WINDOWS", 12_288)
                .and_then(|table| app_for_parent(parent, pid, &table)).or_else(|| parent_app(pid))?;
        }
        Some(result)
    }
    fn atom(&self, name: &std::ffi::CStr) -> c_ulong {
        unsafe { (self.x.XInternAtom)(self.display, name.as_ptr(), xlib::False) }
    }
    fn values(&self, window: c_ulong, name: &std::ffi::CStr, max: usize) -> Option<Vec<c_ulong>> {
        self.typed_values(window, name, max, xlib::XA_CARDINAL)
    }
    fn typed_values(&self, window: c_ulong, name: &std::ffi::CStr, max: usize, expected: c_ulong) -> Option<Vec<c_ulong>> {
        let mut actual = 0; let mut format = 0; let mut count = 0; let mut after = 0; let mut data = ptr::null_mut();
        let status = unsafe { (self.x.XGetWindowProperty)(self.display, window, self.atom(name), 0, max as _,
            xlib::False, expected, &mut actual, &mut format, &mut count, &mut after, &mut data) };
        let valid = status == xlib::Success as c_int && actual == expected && format == 32 && after == 0 && count as usize <= max && !data.is_null();
        let result = if valid { Some(unsafe { std::slice::from_raw_parts(data.cast::<c_ulong>(), count as usize) }.to_vec()) } else { None };
        if !data.is_null() { unsafe { (self.x.XFree)(data.cast()); } }
        result
    }
    fn matches(&self, window: c_ulong) -> bool {
        let mut transient = 0;
        let found = unsafe { (self.x.XGetTransientForHint)(self.display, window, &mut transient) } != 0;
        found && belongs_to_prompt(self.values(window, c"_NET_WM_PID", 1).and_then(|v| v.first().copied()), transient, self.owner, self.parent)
    }
    pub(super) fn update(&mut self) {
        let mut root = 0; let mut parent = 0; let mut children = ptr::null_mut(); let mut count = 0;
        let ok = unsafe { (self.x.XQueryTree)(self.display, self.root, &mut root, &mut parent, &mut children, &mut count) } != 0;
        if ok && !children.is_null() && count <= 4096 {
            // Desktop WMs reparent client windows beneath decoration frames.
            let mut windows = self.typed_values(self.root, c"_NET_CLIENT_LIST", 4096, xlib::XA_WINDOW).unwrap_or_default();
            windows.extend_from_slice(unsafe { std::slice::from_raw_parts(children, count as usize) });
            windows.sort_unstable(); windows.dedup();
            for window in windows {
                if self.changed.iter().any(|entry| entry.0 == window) || !self.matches(window) { continue; }
                let previous = self.values(window, c"STEAM_GAME", 1).and_then(|v| v.first().copied());
                if self.app != 0 {
                    unsafe { (self.x.XChangeProperty)(self.display, window, self.atom(c"STEAM_GAME"), xlib::XA_CARDINAL,
                        32, xlib::PropModeReplace, (&self.app as *const c_ulong).cast(), 1); }
                }
                self.changed.push((window, previous));
            }
            unsafe { (self.x.XFlush)(self.display); }
        }
        if !children.is_null() { unsafe { (self.x.XFree)(children.cast()); } }
    }
    pub(super) fn dismiss(&self) {
        // Some KDE versions unregister a D-Bus prompt without closing its GUI.
        // Request normal closure only for this provider's verified child prompt.
        for &(window, _) in &self.changed {
            if !self.matches(window) { continue; }
            let mut data = xlib::ClientMessageData::new();
            data.set_long(0, self.atom(c"WM_DELETE_WINDOW") as _);
            data.set_long(1, xlib::CurrentTime as _);
            let mut event = xlib::XEvent { client_message: xlib::XClientMessageEvent {
                type_: xlib::ClientMessage, serial: 0, send_event: xlib::True, display: self.display,
                window, message_type: self.atom(c"WM_PROTOCOLS"), format: 32, data,
            } };
            unsafe { (self.x.XSendEvent)(self.display, window, xlib::False, xlib::NoEventMask, &mut event); }
        }
        unsafe { (self.x.XFlush)(self.display); }
    }
}
impl Drop for PromptWindows {
    fn drop(&mut self) {
        for &(window, previous) in &self.changed {
            if self.app == 0 || !self.matches(window) { continue; }
            unsafe {
                if let Some(app) = previous {
                    (self.x.XChangeProperty)(self.display, window, self.atom(c"STEAM_GAME"), xlib::XA_CARDINAL,
                        32, xlib::PropModeReplace, (&app as *const c_ulong).cast(), 1);
                } else { (self.x.XDeleteProperty)(self.display, window, self.atom(c"STEAM_GAME")); }
            }
        }
        unsafe { (self.x.XCloseDisplay)(self.display); }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyring_unlock_prompt_uses_only_the_verified_parent_app() {
        let table = [5, 300, 42, 8, 700, 21];
        assert_eq!(app_for_parent(5, 42, &table), Some(300));
        assert_eq!(app_for_parent(5, 21, &table), None);
        assert_eq!(app_for_parent(7, 42, &table), None);
        assert_eq!(app_for_parent(5, 42, &[5, 0, 42]), None);
        assert_eq!(app_for_parent(5, 42, &[5, 1]), None);
    }
    #[test]
    fn keyring_unlock_prompt_never_tags_unrelated_or_unparented_windows() {
        assert!(belongs_to_prompt(Some(42), 5, 42, 5));
        assert!(!belongs_to_prompt(Some(41), 5, 42, 5));
        assert!(!belongs_to_prompt(Some(42), 6, 42, 5));
        assert!(!belongs_to_prompt(None, 5, 42, 5));
        assert!(!belongs_to_prompt(Some(42), 0, 42, 0));
    }
    #[test]
    fn keyring_unlock_prompt_reaper_id_requires_the_actual_launch_argument() {
        assert_eq!(reaper_app(b"reaper\0SteamLaunch\0AppId=3903927679\0--\0app\0"), Some(3903927679));
        for args in [b"reaper\0AppId=55\0".as_slice(), b"reaper\0SteamLaunch\0--\0AppId=55\0", b"reaper\0SteamLaunch\0AppId=-1\0", b"reaper\0SteamLaunch\0AppId=0\0", b"reaper\0SteamLaunch\0AppId=4294967296\0"] {
            assert_eq!(reaper_app(args), None);
        }
    }
}
