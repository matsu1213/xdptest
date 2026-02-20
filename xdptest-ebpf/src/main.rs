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
    
    if tcp_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // 最大オプション長を 0〜63 の範囲に強制的に収める
    let max_options_len = (tcp_header_len.saturating_sub(20)) & 0x3F;
    let opt_base_offset = EthHdr::LEN + Ipv4Hdr::LEN + 20;

    let window_size = u16::from_be_bytes(unsafe { (*tcphdr).window });

    let mut options = [0u8; 32];
    let mut index = 0usize;
    let mut mss = 0u16;
    let mut wscale = 0u8;
    let mut offset = 0usize;

    let start = ctx.data();
    let end = ctx.data_end();

    // パケットから直接パース（スタックコピー不要）
    for _ in 0..20 {
        // 【重要1】offset を強制的に 0〜63 にバウンドする（var_offエラー回避）
        offset &= 0x3F; 
        if offset >= max_options_len { break; }

        if start + opt_base_offset + offset + 1 > end { break; }
        
        let kind = unsafe { *(start as *const u8).add(opt_base_offset + offset) };
        
        // 【重要2】スタック配列へのアクセスもインデックスを 0〜31 に強制バウンドする
        let idx = index & 0x1F; 
        unsafe { *options.as_mut_ptr().add(idx) = kind; }
        
        if kind == 0 || kind == 1 {
            offset += 1;
            index += 1;
            continue;
        }
        
        if start + opt_base_offset + offset + 2 > end { break; }
        let opt_len = unsafe { *(start as *const u8).add(opt_base_offset + offset + 1) };
        
        if opt_len == 0 { break; } 
        
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
        
        // ここで offset に u8 の値を足すが、次回のループ開始時に `offset &= 0x3F` されるため安全
        offset += opt_len as usize;
        index += 1;
    }

    let ja4t = JA4T::new(window_size, options, mss, wscale);

    let mut ja4t_buf = [0u8; 64];
    let ja4t_len = ja4t.write_to(&mut ja4t_buf);
    
    let final_len = if ja4t_len > 64 { 64 } else { ja4t_len };
    let ja4t_slice = unsafe { core::slice::from_raw_parts(ja4t_buf.as_ptr(), final_len) };
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

        w.push_num(self.window_size);
        w.push(b'_');

        let mut first = true;
        for i in 0..32 {
            // ここも強制バウンド
            let opt = self.options[i & 0x1F]; 
            if opt == 0 { break; }
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
            // 【重要3】バッファへの書き込みインデックスも強制バウンド（var_offエラー回避）
            let p = self.pos & 0x3F; 
            unsafe {
                *self.buf.as_mut_ptr().add(p) = b;
            }
            self.pos += 1;
        }
    }

    #[inline(always)]
    fn push_num(&mut self, mut n: u16) {
        if n == 0 {
            self.push(b'0');
            return;
        }
        let mut tmp = [0u8; 5]; 
        let mut i = 5;
        while n > 0 && i > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        for j in i..5 {
            self.push(tmp[j]);
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