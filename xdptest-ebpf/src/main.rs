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

struct JA4T {
    window_size: u16,
    options: [u8; 8], // 最大8個に絞り込み（状態爆発を防止）
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
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let is_initial_syn = unsafe { (*tcphdr).syn() != 0 && (*tcphdr).ack() == 0 };
    
    if !is_initial_syn {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let doff = unsafe { (*tcphdr).doff() }; 
    let tcp_header_len = (doff as usize) * 4;
    
    if tcp_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let max_options_len = (tcp_header_len.saturating_sub(20)) & 0x3F;
    let opt_base_offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window });

    // 初期値を255にして、パースしたオプションと未初期化を区別する
    let mut options = [255u8; 8];
    let mut opt_idx = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;
    let mut offset = 0usize;

    let start = ctx.data();
    let end = ctx.data_end();

    // 【重要】ループを8回に制限。検証機の計算量が激減します。
    for _ in 0..8 {
        offset &= 0x3F; 
        if offset >= max_options_len { break; }
        if start + opt_base_offset + offset + 1 > end { break; }
        
        let kind = unsafe { *(start as *const u8).add(opt_base_offset + offset) };
        
        let safe_idx = opt_idx & 0x07;
        unsafe { *options.as_mut_ptr().add(safe_idx) = kind; }
        opt_idx += 1;
        
        if kind == 0 { // End Of List
            break;
        } else if kind == 1 { // NOP
            offset += 1;
            continue;
        }
        
        if start + opt_base_offset + offset + 2 > end { break; }
        let opt_len = unsafe { *(start as *const u8).add(opt_base_offset + offset + 1) };
        
        // 不正な長さでの無限ループを防止
        if opt_len < 2 { break; } 
        
        if kind == 2 && opt_len == 4 { // MSS
            if start + opt_base_offset + offset + 4 <= end {
                let b1 = unsafe { *(start as *const u8).add(opt_base_offset + offset + 2) };
                let b2 = unsafe { *(start as *const u8).add(opt_base_offset + offset + 3) };
                mss = u16::from_be_bytes([b1, b2]);
            }
        } else if kind == 3 && opt_len == 3 { // WSCALE
            if start + opt_base_offset + offset + 3 <= end {
                wscale = unsafe { *(start as *const u8).add(opt_base_offset + offset + 2) };
            }
        }
        
        offset += opt_len as usize;
    }

    let ja4t = JA4T { window_size, options, mss, wscale };

    let mut ja4t_buf = [0u8; 64];
    let ja4t_len = ja4t.write_to(&mut ja4t_buf);
    
    let final_len = ja4t_len & 0x3F;
    let ja4t_slice = unsafe { core::slice::from_raw_parts(ja4t_buf.as_ptr(), final_len) };
    let ja4t_str = unsafe { core::str::from_utf8_unchecked(ja4t_slice) };

    info!(&ctx, "SRC IP: {:i}, DST PORT: {}, JA4T: {}", source_addr, dest_port, ja4t_str);

    Ok(xdp_action::XDP_PASS)
}

impl JA4T {
    fn write_to(&self, dst: &mut [u8]) -> usize {
        let mut w = BufWriter { buf: dst, pos: 0 };

        w.push_num(self.window_size);
        w.push(b'_');

        let mut first = true;
        for i in 0..8 {
            let opt = self.options[i];
            if opt == 255 { break; } // 未書き込みの枠に到達したら終了
            if !first {
                w.push(b'-');
            }
            first = false;
            w.push_num(opt as u16);
        }

        w.push(b'_');
        w.push_num(self.mss);
        w.push(b'_');
        w.push_num(self.wscale as u16);

        w.pos
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl BufWriter<'_> {
    #[inline(always)]
    fn push(&mut self, b: u8) {
        if self.pos < 64 {
            let p = self.pos & 0x3F; 
            unsafe {
                *self.buf.as_mut_ptr().add(p) = b;
            }
            self.pos += 1;
        }
    }

    // 【重要】状態爆発を防ぐため、ループを手動展開（アンロール）
    #[inline(always)]
    fn push_num(&mut self, mut n: u16) {
        if n == 0 {
            self.push(b'0');
            return;
        }
        let mut tmp = [0u8; 5]; 
        let mut i = 5;
        
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        if n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
        
        if i <= 0 { self.push(tmp[0]); }
        if i <= 1 { self.push(tmp[1]); }
        if i <= 2 { self.push(tmp[2]); }
        if i <= 3 { self.push(tmp[3]); }
        if i <= 4 { self.push(tmp[4]); }
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