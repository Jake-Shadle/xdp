use crate::libc::mmap;

#[inline]
fn page_size() -> usize {
    use std::sync::atomic;
    static PAGE_SIZE: atomic::AtomicUsize = atomic::AtomicUsize::new(0);

    match PAGE_SIZE.load(atomic::Ordering::Relaxed) {
        0 => {
            let page_size = mmap::sysconf(mmap::_SC_PAGESIZE) as usize;

            PAGE_SIZE.store(page_size, atomic::Ordering::Relaxed);

            page_size
        }
        page_size => page_size,
    }
}

pub struct Mmap {
    pub(crate) ptr: *mut u8,
    len: usize,
}

impl Mmap {
    #[inline]
    pub fn map_umem(length: usize) -> std::io::Result<Self> {
        Self::do_mmmap(
            length,
            0,
            mmap::Flags::MAP_PRIVATE | mmap::Flags::MAP_ANONYMOUS,
            -1,
        )
    }

    #[inline]
    pub fn map_ring(
        length: usize,
        offset: u64,
        socket: std::os::fd::RawFd,
    ) -> std::io::Result<Self> {
        Self::do_mmmap(
            length,
            offset,
            mmap::Flags::MAP_SHARED | mmap::Flags::MAP_POPULATE,
            socket,
        )
    }

    #[inline]
    fn do_mmmap(
        length: usize,
        offset: u64,
        flags: mmap::Flags::Enum,
        file: i32,
    ) -> std::io::Result<Self> {
        // SAFETY: syscalls
        unsafe {
            let alignment = offset % page_size() as u64;
            let aligned_offset = offset - alignment;

            let base = mmap::mmap(
                std::ptr::null_mut(),
                length + alignment as usize,
                mmap::Prot::PROT_READ | mmap::Prot::PROT_WRITE,
                flags,
                file,
                aligned_offset as _,
            );
            if base == mmap::MAP_FAILED {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self {
                    ptr: base.add(alignment as _).cast(),
                    len: length,
                })
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}

//unsafe impl Sync for Mmap {}
unsafe impl Send for Mmap {}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: syscall, the pointer is validated before we create an Mmap
        unsafe { mmap::munmap(self.ptr.cast(), self.len) };
    }
}
