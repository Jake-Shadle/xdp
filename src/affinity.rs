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
        // SAFETY: syscall
        unsafe {
            let mut set = mem::zeroed();

            cpu_set(self.0, &mut set);

            if sched_setaffinity(0, mem::size_of_val(&set), &set) != 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[repr(C)]
struct CpuSet {
    bits: [u64; 16],
}

#[inline]
fn cpu_set(cpu: usize, cpu_set: &mut CpuSet) {
    let size_in_bits = 8 * mem::size_of_val(&cpu_set.bits[0]);
    let (idx, offset) = (cpu / size_in_bits, cpu % size_in_bits);
    cpu_set.bits[idx] |= 1 << offset;
}

#[inline]
fn cpu_is_set(cpu: usize, cpu_set: &CpuSet) -> bool {
    let size_in_bits = 8 * mem::size_of_val(&cpu_set.bits[0]);
    let (idx, offset) = (cpu / size_in_bits, cpu % size_in_bits);
    (cpu_set.bits[idx] & (1 << offset)) != 0
}

unsafe extern "C" {
    fn sched_setaffinity(pid: i32, set_size: usize, mask: *const CpuSet) -> i32;
    fn sched_getaffinity(pid: i32, set_size: usize, mask: *mut CpuSet) -> i32;
}

const CPU_SETSIZE: usize = 0x400;

/// Iterator over the available CPUs
pub struct CoreIds {
    set: CpuSet,
    i: usize,
}

impl CoreIds {
    /// Creates an iterator over the available CPUs
    #[inline]
    pub fn new() -> Result<Self> {
        // SAFETY: syscall
        let set = unsafe {
            let mut set = mem::zeroed();

            if sched_getaffinity(
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
        while self.i < CPU_SETSIZE {
            let available = cpu_is_set(self.i, &self.set);
            self.i += 1;
            if available {
                return Some(CoreId(self.i - 1));
            }
        }

        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.i, Some(CPU_SETSIZE - self.i))
    }
}
