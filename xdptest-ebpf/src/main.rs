#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::{SO_RCVLOWAT, xdp_action}, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr
};

struct JA4T {
    window_size: u16,
    options: [u8; 32],
    mss: u16,
    wscale: u8
}

#[xdp]
pub fn xdptest(ctx: XdpContext) -> u32 {
    match try_xdptest(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdptest(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;

    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;
    
    let max_safe_offset = EthHdr::LEN + Ipv4Hdr::LEN + 60;
    
    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window});

    let mut options = [0u8; 32];
    let mut index = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;

    let start = ctx.data();
    let end = ctx.data_end();

    let read_byte = |off: usize| -> Result<u8, ()> {
        if start + off + 1 > end {
            return Err(());
        }
        Ok(unsafe { *(start as *const u8).add(off) })
    };

    for _ in 0..15 {
        if offset >= EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len { break; }
        if offset >= max_safe_offset { break; }

        let Ok(kind) = read_byte(offset) else { break };
        
        if let Some(opt) = options.get_mut(index) {
            *opt = kind;
        }
        
        offset += 1;

        if kind == 0 || kind == 1 {
            // End of Option List (0) or No-Operation (1)
            index += 1;
            continue;
        } else if kind == 2 {
            // MSS Option (Length 4)
            if offset + 3 > max_safe_offset { break; } // 固定値上限チェック
            
            let Ok(length) = read_byte(offset) else { break };
            if length == 4 {
                if let (Ok(b1), Ok(b2)) = (read_byte(offset + 1), read_byte(offset + 2)) {
                    mss = u16::from_be_bytes([b1, b2]);
                }
            }
            offset += length.saturating_sub(1) as usize; 
        } else if kind == 3 {
            // WSCALE Option (Length 3)
            if offset + 2 > max_safe_offset { break; }
            
            let Ok(length) = read_byte(offset) else { break };
            if length == 3 {
                if let Ok(w) = read_byte(offset + 1) {
                    wscale = w;
                }
            }
            offset += length.saturating_sub(1) as usize;
        } else {
            if offset + 1 > max_safe_offset { break; }
            let Ok(length) = read_byte(offset) else { break };
            if length == 0 { break; } 
            offset += length.saturating_sub(1) as usize;
        }
        index += 1;
    }

    let ja4t = JA4T::new(window_size, options, mss, wscale);

    let mut ja4t_buf = [0u8; 64];
    let ja4t_len = ja4t.write_to(&mut ja4t_buf);
    let ja4t_slice = ja4t_buf.get(..ja4t_len).unwrap_or(&ja4t_buf);
    let ja4t_str = unsafe { core::str::from_utf8_unchecked(ja4t_slice) };

    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}", source_addr, dest_port, ja4t_str);

    Ok(xdp_action::XDP_PASS)
}

impl JA4T {
    fn new(window_size: u16, options: [u8; 32], mss: u16, wscale: u8) -> Self {
        Self { window_size, options, mss, wscale }
    }

    fn write_to(&self, dst: &mut [u8]) -> usize {
        let mut w = BufWriter { buf: dst, pos: 0 };

        w.push_num(self.window_size as u64);
        w.push(b'_');

        let mut first = true;
        for &opt in &self.options {
            if opt == 0 { break; }
            if !first {
                w.push(b'-');
            }
            first = false;
            w.push_num(opt as u64);
        }

        w.push(b'_');
        w.push_num(self.mss as u64);
        w.push(b'_');
        w.push_num(self.wscale as u64);

        w.pos
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl BufWriter<'_> {
    #[inline]
    fn push(&mut self, b: u8) {
        if let Some(byte) = self.buf.get_mut(self.pos) {
            *byte = b;
            self.pos += 1;
        }
    }

    #[inline]
    fn push_bytes(&mut self, bytes: &[u8]) {
        let remain = self.buf.len().saturating_sub(self.pos);
        let len = core::cmp::min(remain, bytes.len());
        
        if let (Some(dst), Some(src)) = (
            self.buf.get_mut(self.pos..self.pos + len),
            bytes.get(..len)
        ) {
            dst.copy_from_slice(src);
            self.pos += len;
        }
    }

    fn push_num(&mut self, mut n: u64) {
        if n == 0 {
            self.push(b'0');
            return;
        }
        
        let mut tmp = [0u8; 20];
        let mut i = 20;
        while n > 0 && i > 0 {
            i -= 1;
            if let Some(byte) = tmp.get_mut(i) {
                *byte = b'0' + (n % 10) as u8;
            }
            n /= 10;
        }
        
        if let Some(slice) = tmp.get(i..) {
            self.push_bytes(slice);
        }
    }
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