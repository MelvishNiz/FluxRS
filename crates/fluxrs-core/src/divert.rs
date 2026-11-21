//! WinDivert based packet redirector (Windows only).
//!
//! WinDivert.dll is loaded at runtime from the executable directory, so the
//! build does not need the WinDivert SDK. `WinDivert64.sys` must sit next to
//! the DLL and the process must run elevated.

#![cfg(windows)]

use crate::nat::{NatTable, Verdict};
use libloading::Library;
use std::ffi::{c_void, CString};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

type Handle = *mut c_void;
const INVALID_HANDLE_VALUE: isize = -1;
const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_SHUTDOWN_BOTH: i32 = 3;
const ERROR_NO_DATA: i32 = 232;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

/// Mirrors `WINDIVERT_ADDRESS` (80 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct WinDivertAddress {
    timestamp: i64,
    /// Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1
    /// IPChecksum:1 TCPChecksum:1 UDPChecksum:1 Reserved1:8
    flags: u32,
    reserved2: u32,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<WinDivertAddress>() == 80);
const OUTBOUND_BIT: u32 = 1 << 17;

impl WinDivertAddress {
    fn zeroed() -> Self {
        WinDivertAddress {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }
    fn outbound(&self) -> bool {
        self.flags & OUTBOUND_BIT != 0
    }
    fn set_outbound(&mut self, v: bool) {
        if v {
            self.flags |= OUTBOUND_BIT;
        } else {
            self.flags &= !OUTBOUND_BIT;
        }
    }
}

type OpenFn = unsafe extern "C" fn(*const std::ffi::c_char, i32, i16, u64) -> Handle;
type RecvFn =
    unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
type SendFn =
    unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const WinDivertAddress) -> i32;
type ShutdownFn = unsafe extern "C" fn(Handle, i32) -> i32;
type CloseFn = unsafe extern "C" fn(Handle) -> i32;
type ChecksumFn = unsafe extern "C" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> i32;

struct Api {
    _lib: Library,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    checksums: ChecksumFn,
}

impl Api {
    fn load() -> Result<Api, String> {
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let dll = dir.join("WinDivert.dll");
        let sys = dir.join("WinDivert64.sys");
        if !dll.exists() || !sys.exists() {
            return Err(format!(
                "WinDivert.dll and WinDivert64.sys must be next to the executable ({})",
                dir.display()
            ));
        }
        // SAFETY: loading a well known library by absolute path.
        let lib = unsafe { Library::new(&dll) }.map_err(|e| format!("load WinDivert.dll: {e}"))?;
        // SAFETY: symbol signatures follow the WinDivert 2.x C API.
        unsafe {
            let open = *lib
                .get::<OpenFn>(b"WinDivertOpen\0")
                .map_err(|e| e.to_string())?;
            let recv = *lib
                .get::<RecvFn>(b"WinDivertRecv\0")
                .map_err(|e| e.to_string())?;
            let send = *lib
                .get::<SendFn>(b"WinDivertSend\0")
                .map_err(|e| e.to_string())?;
            let shutdown = *lib
                .get::<ShutdownFn>(b"WinDivertShutdown\0")
                .map_err(|e| e.to_string())?;
            let close = *lib
                .get::<CloseFn>(b"WinDivertClose\0")
                .map_err(|e| e.to_string())?;
            let checksums = *lib
                .get::<ChecksumFn>(b"WinDivertHelperCalcChecksums\0")
                .map_err(|e| e.to_string())?;
            Ok(Api {
                _lib: lib,
                open,
                recv,
                send,
                shutdown,
                close,
                checksums,
            })
        }
    }
}

fn open_error(code: i32) -> String {
    let hint = match code {
        2 => "driver file WinDivert64.sys not found",
        5 => "access denied - run FluxRS as Administrator",
        87 => "invalid filter or parameter",
        577 => "driver signature rejected (Secure Boot / unsigned driver)",
        654 => "an incompatible WinDivert driver version is already loaded",
        1060 | 1275 => "driver blocked or service missing",
        _ => "unknown error",
    };
    format!("WinDivertOpen failed (code {code}): {hint}")
}

/// Running redirector; stops on drop.
pub struct Redirector {
    api: Arc<Api>,
    handle: isize,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Redirector {
    pub fn start(
        nat: Arc<NatTable>,
        on_error: impl Fn(String) + Send + 'static,
    ) -> Result<Self, String> {
        let api = Arc::new(Api::load()?);
        let filter = CString::new(nat.divert_filter()).map_err(|e| e.to_string())?;
        // SAFETY: valid C string, layer NETWORK, priority 0, flags 0.
        let h = unsafe { (api.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
        if h as isize == INVALID_HANDLE_VALUE || h.is_null() {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(open_error(code));
        }
        let handle = h as isize;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let api = api.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("fluxrs-windivert".into())
                .spawn(move || packet_loop(&api, handle, &nat, &stop, on_error))
                .map_err(|e| e.to_string())?
        };
        Ok(Redirector {
            api,
            handle,
            stop,
            thread: Some(thread),
        })
    }

    pub fn stop(&mut self) {
        if let Some(t) = self.thread.take() {
            self.stop.store(true, Ordering::SeqCst);
            // SAFETY: handle is valid until close below.
            unsafe {
                (self.api.shutdown)(self.handle as Handle, WINDIVERT_SHUTDOWN_BOTH);
            }
            let _ = t.join();
            // SAFETY: thread finished; handle no longer used.
            unsafe {
                (self.api.close)(self.handle as Handle);
            }
        }
    }
}

impl Drop for Redirector {
    fn drop(&mut self) {
        self.stop();
    }
}

fn packet_loop(
    api: &Api,
    handle: isize,
    nat: &NatTable,
    stop: &AtomicBool,
    on_error: impl Fn(String),
) {
    let h = handle as Handle;
    let mut buf = vec![0u8; 0xFFFF];
    let mut error_count = 0u32;
    loop {
        let mut addr = WinDivertAddress::zeroed();
        let mut len: u32 = 0;
        // SAFETY: buffer and addr are valid for the call duration.
        let ok = unsafe {
            (api.recv)(
                h,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut len,
                &mut addr,
            )
        };
        if ok == 0 {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if stop.load(Ordering::SeqCst) || code == ERROR_NO_DATA {
                break;
            }
            if code != ERROR_INSUFFICIENT_BUFFER {
                error_count += 1;
                if error_count <= 5 {
                    on_error(format!("WinDivertRecv failed (code {code})"));
                }
                if error_count > 1000 {
                    on_error("Too many WinDivert errors, capture stopped".into());
                    break;
                }
            }
            continue;
        }
        let len = (len as usize).min(buf.len());
        let pkt = &mut buf[..len];
        let mut outbound = addr.outbound();
        match nat.process(pkt, &mut outbound) {
            Verdict::Drop => continue,
            Verdict::Pass => {}
            Verdict::Modified => {
                addr.set_outbound(outbound);
                // SAFETY: valid packet buffer and address.
                unsafe {
                    (api.checksums)(pkt.as_mut_ptr() as *mut c_void, len as u32, &mut addr, 0);
                }
            }
        }
        // SAFETY: valid packet buffer and address.
        unsafe {
            (api.send)(
                h,
                pkt.as_ptr() as *const c_void,
                len as u32,
                std::ptr::null_mut(),
                &addr,
            );
        }
    }
}
