//! Core affinity helpers

use std::{
    io::{Error, Result},
    mem,
};

/// A logical CPU id
#[derive(Copy, Clone)]
pub struct CoreId(pub usize);

impl CoreId {
    /// Sets the core affinity for the current thread
    #[inline]
    pub fn set_affinity(self) -> Result<()> {
        unsafe {
            let mut set = mem::zeroed();

            libc::CPU_SET(self.0, &mut set);

            if libc::sched_setaffinity(0, mem::size_of_val(&set), &set) != 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

/// Iterator over the available CPUs
pub struct CoreIds {
    set: libc::cpu_set_t,
    i: usize,
}

impl CoreIds {
    /// Creates an iterator over the available CPUs
    #[inline]
    pub fn new() -> Result<Self> {
        let set = unsafe {
            let mut set = mem::zeroed();

            if libc::sched_getaffinity(
                0, // Defaults to current thread
                std::mem::size_of_val(&set),
                &mut set,
            ) != 0
            {
                return Err(Error::last_os_error());
            }

            set
        };

        Ok(Self { set, i: 0 })
    }
}

impl Iterator for CoreIds {
    type Item = CoreId;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.i < libc::CPU_SETSIZE as usize {
            let available = unsafe { libc::CPU_ISSET(self.i, &self.set) };
            self.i += 1;
            if available {
                return Some(CoreId(self.i - 1));
            }
        }

        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.i, Some(libc::CPU_SETSIZE as usize - self.i))
    }
}
