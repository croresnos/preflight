//! Audited Job Object ownership. This module configures and queries every
//! resource flag before it may be handed to a process-launch transaction.

use std::io;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use blast_chambers_protocol::Limits;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};

#[derive(Debug)]
pub struct Job {
    handle: HANDLE,
}

impl Job {
    /// Create a Job Object, configure every requested limit, and read it back.
    ///
    /// # Errors
    ///
    /// Returns an OS or validation error if any limit cannot be proven.
    pub fn configured(limits: &Limits) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // SAFETY: null security/name pointers request an unnamed, non-inheritable
        // kernel object. The returned owned handle is checked and closed by Drop.
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        if let Err(error) = job.configure_and_verify(limits) {
            let _ = job.terminate(0xC000_0001);
            return Err(error);
        }
        Ok(job)
    }

    fn configure_and_verify(&self, limits: &Limits) -> io::Result<()> {
        // SAFETY: the structure is plain C data and all fields are initialized
        // before its address and exact size are passed to the Win32 API.
        let mut configured: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        configured.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_JOB_TIME;
        configured.BasicLimitInformation.ActiveProcessLimit = limits.active_process_limit;
        configured.BasicLimitInformation.PerJobUserTimeLimit =
            i64::try_from(limits.cpu_time_ms.saturating_mul(10_000)).unwrap_or(i64::MAX);
        configured.ProcessMemoryLimit = usize::try_from(limits.process_memory_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process memory overflow"))?;
        configured.JobMemoryLimit = usize::try_from(limits.job_memory_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "job memory overflow"))?;
        set_job(self.handle, JobObjectExtendedLimitInformation, &configured)?;

        let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            ..Default::default()
        };
        cpu.Anonymous.CpuRate = limits.cpu_rate_percent * 100;
        set_job(self.handle, JobObjectCpuRateControlInformation, &cpu)?;

        let actual: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            query_job(self.handle, JobObjectExtendedLimitInformation)?;
        if actual.BasicLimitInformation.LimitFlags != configured.BasicLimitInformation.LimitFlags
            || actual.BasicLimitInformation.ActiveProcessLimit
                != configured.BasicLimitInformation.ActiveProcessLimit
            || actual.BasicLimitInformation.PerJobUserTimeLimit
                != configured.BasicLimitInformation.PerJobUserTimeLimit
            || actual.ProcessMemoryLimit != configured.ProcessMemoryLimit
            || actual.JobMemoryLimit != configured.JobMemoryLimit
        {
            return Err(io::Error::other(
                "Job Object limits failed read-back verification",
            ));
        }
        let actual_cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION =
            query_job(self.handle, JobObjectCpuRateControlInformation)?;
        // SAFETY: CpuRate is the active union member when HARD_CAP is set.
        let rate = unsafe { actual_cpu.Anonymous.CpuRate };
        if actual_cpu.ControlFlags != cpu.ControlFlags || rate != limits.cpu_rate_percent * 100 {
            return Err(io::Error::other(
                "Job Object CPU limit failed read-back verification",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Assign a suspended process and verify membership before it can resume.
    ///
    /// # Errors
    ///
    /// Returns the Win32 error when assignment or membership verification
    /// fails. The caller must terminate its still-suspended process on error.
    ///
    /// # Safety
    ///
    /// `process` must be a valid process handle whose primary thread has not
    /// been resumed, and it must stay valid for the duration of this call.
    pub unsafe fn assign_and_verify(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are borrowed, valid kernel handles.
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut member = 0;
        // SAFETY: member is writable and both handles remain valid.
        if unsafe { IsProcessInJob(process, self.handle, &raw mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if member == 0 {
            return Err(io::Error::other(
                "process was not a Job Object member after assignment",
            ));
        }
        Ok(())
    }

    /// Terminate every process that remains in this job.
    ///
    /// # Errors
    ///
    /// Returns the Win32 error when termination is not confirmed.
    pub fn terminate(&self, code: u32) -> io::Result<()> {
        // SAFETY: handle is owned and valid for the lifetime of self.
        if unsafe { TerminateJobObject(self.handle, code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: handle is uniquely owned. KILL_ON_JOB_CLOSE makes this the
        // final fail-closed process-tree boundary.
        unsafe { CloseHandle(self.handle) };
    }
}

fn set_job<T>(handle: HANDLE, class: i32, value: &T) -> io::Result<()> {
    let size = u32::try_from(size_of::<T>())
        .map_err(|_| io::Error::other("Job Object structure size overflow"))?;
    // SAFETY: caller supplies the information structure corresponding to class.
    let ok =
        unsafe { SetInformationJobObject(handle, class, std::ptr::from_ref(value).cast(), size) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn query_job<T>(handle: HANDLE, class: i32) -> io::Result<T> {
    // SAFETY: output points to writable storage of the exact reported size.
    let mut value: T = unsafe { zeroed() };
    let size = u32::try_from(size_of::<T>())
        .map_err(|_| io::Error::other("Job Object structure size overflow"))?;
    let ok = unsafe {
        QueryInformationJobObject(
            handle,
            class,
            std::ptr::from_mut(&mut value).cast(),
            size,
            null_mut(),
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess,
        PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    fn limits() -> Limits {
        Limits {
            wall_time_ms: 5_000,
            cpu_time_ms: 5_000,
            cpu_rate_percent: 50,
            process_memory_bytes: 64 * 1024 * 1024,
            job_memory_bytes: 128 * 1024 * 1024,
            active_process_limit: 2,
            output_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn suspended_process_is_assigned_before_resume() {
        let job = Job::configured(&limits()).unwrap();
        let mut command: Vec<u16> = "cmd.exe /d /c exit 0\0".encode_utf16().collect();
        // SAFETY: both structures are plain C data and are initialized below.
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).unwrap();
        // SAFETY: PROCESS_INFORMATION is an output-only C structure.
        let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: command is mutable and NUL-terminated; all optional pointers
        // are null; no handles are inherited.
        let created = unsafe {
            CreateProcessW(
                null(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                null(),
                null(),
                &raw const startup,
                &raw mut process,
            )
        };
        assert_ne!(created, 0, "CreateProcessW: {}", io::Error::last_os_error());
        // SAFETY: CreateProcessW returned this owned process handle and its
        // primary thread is still suspended.
        if let Err(error) = unsafe { job.assign_and_verify(process.hProcess) } {
            // SAFETY: process was successfully created and is still suspended.
            unsafe { TerminateProcess(process.hProcess, 1) };
            panic!("assignment failed: {error}");
        }
        // SAFETY: hThread is the suspended primary thread we own.
        assert_ne!(unsafe { ResumeThread(process.hThread) }, u32::MAX);
        // SAFETY: hProcess is valid until closed below.
        assert_eq!(
            unsafe { WaitForSingleObject(process.hProcess, 5_000) },
            WAIT_OBJECT_0
        );
        let mut exit_code = u32::MAX;
        // SAFETY: exit_code is writable and process handle is valid.
        assert_ne!(
            unsafe { GetExitCodeProcess(process.hProcess, &raw mut exit_code) },
            0
        );
        // SAFETY: both returned handles are uniquely owned by this test.
        unsafe {
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        assert_eq!(exit_code, 0);
    }
}
