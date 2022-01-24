#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp(name = "pass")]
fn pass(_ctx: XdpContext) -> u32 {
    return xdp_action::XDP_PASS;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
