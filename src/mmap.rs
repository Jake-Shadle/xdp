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
    addr: *mut std::ffi::c_void,
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
                    addr: base.add(alignment as _),
                    len: length,
                })
            }
        }
    }
}

unsafe impl Sync for Mmap {}
unsafe impl Send for Mmap {}

impl std::ops::Deref for Mmap {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.addr.cast(), self.len) }
    }
}

impl std::ops::DerefMut for Mmap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.addr.cast(), self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe { mmap::munmap(self.addr, self.len) };
    }
}
