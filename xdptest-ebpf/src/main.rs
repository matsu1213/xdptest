#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn xdptest(ctx: XdpContext) -> u32 {
    match try_xdptest(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdptest(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            //let udphdr: *const UdpHdr =
            //    ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            //unsafe { (*udphdr).dst_port() }
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Err(()),
    };

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;

    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;
    let options_end = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len;

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window});

    let mut options = Vec::new();
    

    // (3)
    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, FLAG: {}", source_addr, source_port, "SYN");

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}



#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
