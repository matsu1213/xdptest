#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr
};

#[xdp]
pub fn xdptest(ctx: XdpContext) -> u32 {
    match try_xdptest(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdptest(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl_words = unsafe { (*ipv4hdr).ihl() } as usize;
    let ipv4_header_len = ihl_words * 4;
    if ipv4_header_len < Ipv4Hdr::LEN {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_offset = EthHdr::LEN + ipv4_header_len;
    let tcphdr: *const TcpHdr = ptr_at(&ctx, tcp_offset)?;
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window });

    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;
    
    if tcp_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let mut max_options_len = tcp_header_len.saturating_sub(20);
    if max_options_len > 40 { max_options_len = 40; }
    
    let opt_base_offset = tcp_offset + 20;

    let mut options = [255u8; 8];
    let mut opt_idx = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;
    let mut offset = 0usize;
    let start = ctx.data();
    let end = ctx.data_end();

    for _ in 0..8 {
        if offset >= max_options_len { break; }
        if offset > 40 { break; }

        let curr_ptr = start + opt_base_offset + offset;
        if curr_ptr + 1 > end {
            break;
        }

        let kind = unsafe { core::ptr::read_volatile(curr_ptr as *const u8) };
        
        if kind == 0 { break; }

        if opt_idx < 8 {
            options[opt_idx] = kind;
            opt_idx += 1;
        }

        if kind == 1 {
            offset += 1;
            continue;
        }

        if curr_ptr + 2 > end {
            break;
        }
        let opt_len = unsafe { core::ptr::read_volatile((curr_ptr + 1) as *const u8) };
        
        if opt_len < 2 { break; }
        
        let next_offset = offset + opt_len as usize;
        if next_offset > max_options_len {
            break;
        }

        if kind == 2 && opt_len == 4 {
            if curr_ptr + 4 > end {
                break;
            }
            let b1 = unsafe { core::ptr::read_volatile((curr_ptr + 2) as *const u8) };
            let b2 = unsafe { core::ptr::read_volatile((curr_ptr + 3) as *const u8) };
            mss = u16::from_be_bytes([b1, b2]);
        } else if kind == 3 && opt_len == 3 {
            if curr_ptr + 3 > end {
                break;
            }
            wscale = unsafe { core::ptr::read_volatile((curr_ptr + 2) as *const u8) };
        }

        offset = next_offset;
    }

    match opt_idx {
        0 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}__{}_{}", source_addr, dest_port, window_size, mss, wscale),
        1 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}_{}_{}", source_addr, dest_port, window_size, options[0], mss, wscale),
        2 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], mss, wscale),
        3 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], mss, wscale),
        4 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], options[3], mss, wscale),
        5 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], options[3], options[4], mss, wscale),
        6 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}-{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], options[3], options[4], options[5], mss, wscale),
        7 => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}-{}-{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], options[3], options[4], options[5], options[6], mss, wscale),
        _ => info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}_{}-{}-{}-{}-{}-{}-{}-{}_{}_{}", source_addr, dest_port, window_size, options[0], options[1], options[2], options[3], options[4], options[5], options[6], options[7], mss, wscale),
    };

    Ok(xdp_action::XDP_PASS)
}


#[inline(always)]
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