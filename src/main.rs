extern crate goblin;
extern crate reqwest;
extern crate indicatif;

use indicatif::{ProgressBar, ProgressStyle};


use goblin::error;
use std::path::Path;
use std::env;
use std::fs::File;
use std::io::Read;
use std::ffi::CStr;

use reqwest::Client;
use reqwest::header::{ContentLength, UserAgent};


fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let mut fd = File::open(path)?;
            let buffer = { let mut v = Vec::new(); fd.read_to_end(&mut v).unwrap(); v};
            let res = goblin::Object::parse(&buffer)?;
            //match res {
            //    goblin::Object::PE(goblin::pe::PE { debug_data: Some()})
            //}
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

            //println!("{:#?} {:?}", file, guid);

            let url = format!("{}/{}/{}/{}", "https://msdl.microsoft.com/download/symbols", file, guid_str, file);
            let mut res = Client::new().get(&url).header(UserAgent::new("Microsoft-Symbol-Server/6.11.0001.402")).send();
            if let Ok(mut response) = res {
                let size = response.headers().get::<ContentLength>().map(|ct_len| **ct_len).unwrap();
                let mut f = File::create(file).unwrap();
                let pb = ProgressBar::new(size);
                pb.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .progress_chars("#>-"));

                struct ProgressWriter<'a> {
                    writer: &'a mut std::io::Write,
                    bar: ProgressBar,
                    cur_size: usize,
                }
                let mut p = ProgressWriter { writer: &mut f, bar: pb, cur_size: 0};
                impl<'a> std::io::Write for ProgressWriter<'a> {
                    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                        let ret = self.writer.write(buf);
                        if let Ok(size) = ret {
                            self.cur_size += size;
                            self.bar.set_position(self.cur_size as u64);
                        }
                        ret
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        self.writer.flush()
                    }

                }
                response.copy_to(&mut p);
            }
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
