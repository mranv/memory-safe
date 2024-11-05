use std::alloc::{alloc, dealloc, Layout};
use std::ptr;

// Platform-specific page size function
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(target_os = "windows")]
fn get_page_size() -> usize {
    use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        system_info.dwPageSize as usize
    }
}

// Memory protection flags for different platforms
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod protection {
    pub const READ: i32 = libc::PROT_READ;
    pub const WRITE: i32 = libc::PROT_WRITE;
    pub const EXEC: i32 = libc::PROT_EXEC;
}

#[cfg(target_os = "windows")]
mod protection {
    use winapi::um::winnt;
    pub const READ: u32 = winnt::PAGE_READONLY;
    pub const WRITE: u32 = winnt::PAGE_READWRITE;
    pub const EXEC: u32 = winnt::PAGE_EXECUTE_READ;
}

// Safe wrapper for memory page allocation
pub struct SafeMemoryPage {
    ptr: *mut u8,
    layout: Layout,
    size: usize,
}

impl SafeMemoryPage {
    pub fn new(size: usize) -> Option<Self> {
        let page_size = get_page_size();
        // Round up to nearest page size
        let aligned_size = (size + page_size - 1) & !(page_size - 1);
        
        let layout = Layout::from_size_align(aligned_size, page_size).ok()?;
        
        // Safety: Layout is guaranteed to be valid
        let ptr = unsafe { alloc(layout) };
        
        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                layout,
                size: aligned_size,
            })
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn set_protection(&mut self, can_read: bool, can_write: bool, can_exec: bool) -> bool {
        let mut prot = 0;
        if can_read { prot |= protection::READ; }
        if can_write { prot |= protection::WRITE; }
        if can_exec { prot |= protection::EXEC; }

        unsafe {
            libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.size,
                prot
            ) == 0
        }
    }

    #[cfg(target_os = "windows")]
    pub fn set_protection(&mut self, can_read: bool, can_write: bool, can_exec: bool) -> bool {
        use winapi::um::memoryapi::VirtualProtect;
        let mut prot = if can_exec {
            protection::EXEC
        } else if can_write {
            protection::WRITE
        } else if can_read {
            protection::READ
        } else {
            return false;
        };

        let mut old_protect = 0;
        unsafe {
            VirtualProtect(
                self.ptr as *mut _,
                self.size,
                prot,
                &mut old_protect
            ) != 0
        }
    }
    
    pub fn read(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        if offset + len > self.layout.size() {
            return None;
        }
        
        let mut buffer = vec![0u8; len];
        unsafe {
            ptr::copy_nonoverlapping(
                self.ptr.add(offset),
                buffer.as_mut_ptr(),
                len
            );
        }
        Some(buffer)
    }
    
    pub fn write(&mut self, offset: usize, data: &[u8]) -> bool {
        if offset + data.len() > self.layout.size() {
            return false;
        }
        
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.add(offset),
                data.len()
            );
        }
        true
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for SafeMemoryPage {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

fn main() {
    println!("System page size: {} bytes", get_page_size());
    
    // Allocate a memory page
    let mut page = SafeMemoryPage::new(4096)
        .expect("Failed to allocate memory page");
    
    // Set memory protection (read/write access)
    page.set_protection(true, true, false);
    
    // Example data to write
    let data = b"Hello, Cross-Platform Memory Management!";
    
    // Write data safely
    if page.write(0, data) {
        println!("Successfully wrote data to memory page");
        
        // Read back the data
        if let Some(read_data) = page.read(0, data.len()) {
            let text = String::from_utf8_lossy(&read_data);
            println!("Read data: {}", text);
        }
    }
    
    println!("Memory page size: {} bytes", page.size());
}