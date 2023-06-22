use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_ulong};
use std::ptr;
use std::io::{Error};

use morello::capability::Capability;

pub fn get_root_seal(sealcap: *mut Capability, sealcap_size: usize) -> Result<(), Error> {

        
    // Get the sealing capability
    let result = unsafe {
        sysctlbyname(
            "security.cheri.sealcap\0".as_ptr(),
            sealcap as *mut c_void,
            &sealcap_size,
            ptr::null_mut(),
            0,
        )
    };
    
    if result < 0 {
        return Err(Error::last_os_error())
    } else {
        return Ok(())
    }
}

extern "C" {
    fn sysctlbyname(
        name: *const u8,
        oldp: *mut c_void,
        oldlenp: *const usize,
        newp: *const c_void,
        newlen: c_ulong,
    ) -> c_int;
}