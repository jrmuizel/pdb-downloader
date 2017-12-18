extern crate goblin;


use goblin::error;
use std::path::Path;
use std::env;
use std::fs::File;
use std::io::Read;
use std::ffi::CStr;


fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let mut fd = File::open(path)?;
            let buffer = { let mut v = Vec::new(); fd.read_to_end(&mut v).unwrap(); v};
            let res = goblin::Object::parse(&buffer)?;
            match res {
                goblin::Object::PE(goblin::pe::PE { debug_data: Some()})
            }
            let pe = match res {
                goblin::Object::PE(pe) => { pe }
                _ => { panic!() }
            };

            let codeview_info = pe.debug_data.unwrap().codeview_pdb70_debug_info.unwrap();
            let file = codeview_info.filename;

            let age = codeview_info.age;

            let guid = codeview_info.signature;
            let guid_str = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                                   guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6],
                                    guid[8],guid[9],guid[10],guid[11],guid[12],guid[13],guid[14], guid[15], age);
            let file = CStr::from_bytes_with_nul(file).unwrap().to_str().unwrap();

            println!("{:#?} {:?}", file, guid);
            println!("curl -sA \"{}\" \"{}/{}/{}/{}\" -o \"{}\"",
                "Microsoft-Symbol-Server/6.11.0001.402",
                "https://msdl.microsoft.com/download/symbols",
                file,
                guid_str, file, file);
        }
    }
    Ok(())
}

pub fn main () {
    //env_logger::init().unwrap();
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:#}", err)
    }
}
