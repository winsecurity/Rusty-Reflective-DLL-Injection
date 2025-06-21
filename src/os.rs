use ntapi::ntrtl::*;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::winnt::*;

pub fn getosversion() -> Result<OSVERSIONINFOW,String>{

    let mut osversion = unsafe{std::mem::zeroed::<OSVERSIONINFOW>()};
    osversion.dwOSVersionInfoSize = std::mem::size_of_val(&osversion) as u32;
    let res = unsafe{RtlGetVersion(&mut osversion)};
    if NT_SUCCESS(res){
        Ok(osversion)
    }
    else{
        Err(format!("getting os version failed: {}",res))
    }

}


pub fn runfile(filename: &str) -> String{

    let res = std::process::Command::new("powershell")
        .args([filename])
        .output();

    if res.is_ok(){
        let cmd = res.unwrap();
        if cmd.stdout.len()>=1{
            String::from_utf8_lossy(&cmd.stdout).trim().to_string()
        }
        else{
            String::from_utf8_lossy(&cmd.stderr).trim().to_string()
        }

    }
    else{
        format!("Something went wrong")
    }
}


pub fn runfile_with_arg(filename: &str,argument:&str) -> String{

    let res = std::process::Command::new("powershell")
        .args([filename,argument])
        .output();

    if res.is_ok(){
        let cmd = res.unwrap();
        if cmd.stdout.len()>=1{
            String::from_utf8_lossy(&cmd.stdout).trim().to_string()
        }
        else{
            String::from_utf8_lossy(&cmd.stderr).trim().to_string()
        }

    }
    else{
        format!("Something went wrong")
    }
}



