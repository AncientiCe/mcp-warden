//! Keep the proxy and its descendants in a job whose sole handle belongs to
//! the proxy. Windows closes it even on TerminateProcess, killing descendants.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Mutex;

use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// Static storage deliberately lasts until process exit. Dropping this handle
// sooner would kill the proxy itself and replace the wrapped server's exit code.
static PROCESS_JOB: Mutex<Option<OwnedHandle>> = Mutex::new(None);

pub fn contain_process_tree() -> io::Result<()> {
    let mut stored = PROCESS_JOB
        .lock()
        .map_err(|_| io::Error::other("process job lock poisoned"))?;
    if stored.is_some() {
        return Ok(());
    }
    // SAFETY: null attributes create a non-inheritable, unnamed job. The returned
    // handle is checked and transferred to a single OwnedHandle.
    let job = unsafe {
        let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(handle)
    };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the buffer and size match the requested information class and the
    // job handle stays valid. Assignment happens before spawning any server,
    // so children inherit membership without a spawn-to-assignment race.
    unsafe {
        if SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    *stored = Some(job);
    Ok(())
}
