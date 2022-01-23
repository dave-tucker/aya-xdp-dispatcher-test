#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, xdp_md},
    macros::xdp,
    programs::XdpContext,
    BpfContext,
};

use dispatcher_test_common::*;

#[no_mangle]
static CONFIG: XdpDispatcherConfig = XdpDispatcherConfig {
    num_progs_enabled: 0,
    chain_call_actions: [0; MAX_DISPATCHER_ACTIONS],
    run_prios: [0; MAX_DISPATCHER_ACTIONS],
};

#[no_mangle]
#[inline(never)]
pub fn prog0(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
    let ret = XDP_DISPATCHER_RETVAL;
    if ctx.is_null() {
        return xdp_action::XDP_ABORTED;
    }
    return ret;
}

#[xdp(name = "dispatcher")]
fn dispatcher(ctx: XdpContext) -> u32 {
    let cfg = &CONFIG as *const XdpDispatcherConfig;
    let current_cfg = unsafe { core::ptr::read_volatile(&cfg)};
    let num_progs_enabled = unsafe { (*current_cfg).num_progs_enabled };
    if num_progs_enabled < 1 {
        return xdp_action::XDP_PASS
    }
    let ret = prog0(ctx.as_ptr() as *mut xdp_md);
    if (1 << ret) & unsafe { (*current_cfg).chain_call_actions[0] } == 0 {
        return ret;
    }
    return xdp_action::XDP_PASS;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
