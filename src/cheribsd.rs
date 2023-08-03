use std::os::raw::{c_void};
use std::ptr;
use std::io::{Error};
use libc::{sysctlbyname};


pub fn get_root_seal<T>(sealcap: *mut T, sealcap_size: *mut usize) -> Result<(), Error> {


    // Get the sealing capability
    let result = unsafe {

        sysctlbyname(
            "security.cheri.sealcap\0".as_ptr() as *const u8,
            sealcap as *mut c_void,
            sealcap_size,
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