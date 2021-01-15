use core::time::Duration;
use std::str;

use chrono::Local;
use anyhow::Result;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use structopt::StructOpt;

mod bpf;
use bpf::*;

#[derive(Debug, StructOpt)]
struct Command {
    // Hello world in Español
    #[structopt(short = "E", long = "es")]
    en_espanol: bool,
}

#[repr(C)]
#[derive(Default)]
struct Event {
    pub pid: i32,
    pub msg: [u8; 32],
}
unsafe impl Plain for Event {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let now = Local::now();
    let mut event: Event = Event::default();
    // println!("{:?}", data);
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let msg = str::from_utf8(&event.msg).unwrap().trim_end_matches('\0');
    println!("{:31}: {:<6} {}", now.to_rfc2822(), event.pid, msg);
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let mut skel_builder: HelloworldSkelBuilder = HelloworldSkelBuilder::default();
    let mut open_skel: OpenHelloworldSkel = skel_builder.open()?;

    open_skel.rodata().espanol = if opts.en_espanol { 1 } else { 0 };
    let mut skel = open_skel.load()?;
    skel.attach()?;
    println!("{:32} {:6} MSG", "TIME", "PID");

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
