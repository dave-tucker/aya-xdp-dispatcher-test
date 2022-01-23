use aya::{BpfLoader, include_bytes_aligned};
use anyhow::Context;
use aya::programs::{Extension, ProgramFd, Xdp, XdpFlags};
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::convert::TryInto;
use structopt::StructOpt;
use tokio::signal;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "wlp2s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = BpfLoader::new().extension("pass").load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/dispatcher-test"
    ))?;
    let program: &mut Xdp = bpf.program_mut("dispatcher").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut bpf = BpfLoader::new().extension("pass").load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/pass"
    ))?;
    let ext: &mut Extension = bpf.program_mut("pass").unwrap().try_into()?;
    ext.load(program.fd().unwrap(), "prog0")?;
    ext.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
