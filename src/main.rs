extern crate goblin;
extern crate indicatif;
extern crate reqwest;

use indicatif::{ProgressBar, ProgressStyle};

use goblin::error;
use std::env;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use reqwest::header::{CONTENT_LENGTH, USER_AGENT};
use reqwest::Client;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PdbDownloaderError {
    #[error("error parsing PE")]
    PEParseError(#[from] error::Error),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("request error")]
    RequestError(#[from] reqwest::Error),
    #[error("unknown pdb error")]
    Unknown,
}

type PdbDownloaderResult<T> = Result<T, PdbDownloaderError>;

struct ProgressWriter<'a> {
    writer: &'a mut dyn std::io::Write,
    bar: ProgressBar,
    cur_size: usize,
}

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

#[tokio::main]
async fn run() -> PdbDownloaderResult<()> {
    for (i, arg) in env::args().enumerate() {
        if i != 1 {
            continue;
        }
        let path = Path::new(arg.as_str());
        let mut fd = File::open(path)?;
        let buffer = {
            let mut v = Vec::new();
            fd.read_to_end(&mut v).unwrap();
            v
        };
        let res = goblin::Object::parse(&buffer)?;

        let pe = if let goblin::Object::PE(pe) = res {
            pe
        } else {
            panic!(format!("unable to parse PE file: {:?}", path));
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

        let url = format!(
            "{}/{}/{}/{}",
            "https://msdl.microsoft.com/download/symbols", file, guid_str, file
        );

        let mut res = Client::new()
            .get(&url)
            .header(USER_AGENT, "Microsoft-Symbol-Server/6.11.0001.402")
            .send()
            .await?;

        let size = res
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|ct_len| u64::from_str_radix(ct_len.to_str().unwrap(), 10).ok())
            .unwrap();

        let mut f = File::create(file).unwrap();
        let pb = ProgressBar::new(size);

        pb.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .progress_chars("#>-"));

        let mut p = ProgressWriter {
            writer: &mut f,
            bar: pb,
            cur_size: 0,
        };

        while let Some(chunk) = res.chunk().await? {
            p.write(&chunk)?;
        }

        p.flush()?;
    }

    Ok(())
}

pub fn main() {
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:#}", err),
    }
}
