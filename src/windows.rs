use std::{
  collections::VecDeque,
  io::ErrorKind,
  net::Ipv4Addr,
  sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc,
  },
  thread::JoinHandle,
};

pub fn set_ip_address(
  adapter: &Arc<Adapter>,
  internal_ip: Ipv4Addr,
  mask: u8,
) -> std::io::Result<()> {
  let mut address_row = winapi::shared::netioapi::MIB_UNICASTIPADDRESS_ROW::default();
  unsafe {
    winapi::shared::netioapi::InitializeUnicastIpAddressEntry(&mut address_row as *mut _);
  }
  const IP_SUFFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_SUFFIX_ORIGIN = 3;
  const IP_PREFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_PREFIX_ORIGIN = 3;
  address_row.SuffixOrigin = IP_SUFFIX_ORIGIN_DHCP;
  address_row.PrefixOrigin = IP_PREFIX_ORIGIN_DHCP;
  const LIFETIME_INFINITE: winapi::ctypes::c_ulong = 0xffffffff;
  address_row.ValidLifetime = LIFETIME_INFINITE;
  address_row.PreferredLifetime = LIFETIME_INFINITE;
  address_row.InterfaceLuid = adapter.get_luid();
  unsafe {
    let ipv4 = address_row.Address.Ipv4_mut();
    ipv4.sin_family = winapi::shared::ws2def::AF_INET as _;
    *ipv4.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(internal_ip.octets());
  }
  address_row.OnLinkPrefixLength = mask;
  address_row.DadState = winapi::shared::nldef::IpDadStatePreferred;
  let error =
    unsafe { winapi::shared::netioapi::CreateUnicastIpAddressEntry(&mut address_row as *mut _) };
  if error != winapi::shared::winerror::ERROR_SUCCESS {
    return Err(std::io::Error::new(
      ErrorKind::AddrNotAvailable,
      format!(
        "Failed to set IP address: {:?}",
        get_last_error::Win32Error::new(error)
      ),
    ));
  }
  Ok(())
}

use wtun::{ring_capacity, Adapter, Session, MAX_RING_CAPACITY};

pub struct Tun {
  session: Arc<Session>,
  adapter: Box<Adapter>,
  in_tx: Option<Sender<Vec<u8>>>,
  out_rx: Option<Receiver<Vec<u8>>>,
  thread: Option<JoinHandle<std::io::Result<()>>>,
  terminate: Arc<AtomicBool>,
}

pub struct TunSender {
  tx: Sender<Vec<u8>>,
}

impl TunSender {
  pub fn send(&self, packet: Vec<u8>) {
    drop(self.tx.send(packet));
  }
}

impl Tun {
  pub fn from_adapter(mut adapter: Box<Adapter>) -> std::io::Result<Self> {
    let session = adapter.start_session_wrapped(ring_capacity!(MAX_RING_CAPACITY))?;
    Ok(Self {
      session,
      adapter,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
  }
  pub fn new(
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    let mut adapter = Adapter::create(name.as_ref(), pool.as_ref(), None)?;
    adapter.set_ip_address(wtun::IpAndMaskPrefix::V4 {
      ip,
      prefix: mask
        .try_into()
        .ok()
        .ok_or(std::io::ErrorKind::InvalidInput)?,
    })?;
    let session = adapter.start_session_wrapped(ring_capacity!(MAX_RING_CAPACITY))?;
    Ok(Self {
      session,
      adapter,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
  }
  pub fn recv(&self) -> Option<Vec<u8>> {
    self.out_rx.as_ref().unwrap().try_recv().ok()
  }
  pub fn iter(&self) -> mpsc::TryIter<Vec<u8>> {
    self.out_rx.as_ref().unwrap().try_iter()
  }
  pub fn send(&self, packet: Vec<u8>) {
    drop(self.in_tx.as_ref().unwrap().send(packet));
  }
  pub fn is_registered(&self) -> bool {
    !self.terminate.load(Ordering::Relaxed)
  }
  pub fn sender(&self) -> TunSender {
    TunSender {
      tx: self.in_tx.as_ref().unwrap().clone(),
    }
  }
  pub fn adapter(&self) -> &Adapter {
    &self.adapter
  }
}

impl Drop for Tun {
  fn drop(&mut self) {
    self.terminate.store(true, Ordering::Relaxed);
    if let Some(thread) = std::mem::replace(&mut self.thread, None) {
      drop(thread.join());
    }
  }
}

impl mio::event::Source for Tun {
  fn register(
    &mut self,
    registry: &mio::Registry,
    token: mio::Token,
    interests: mio::Interest,
  ) -> std::io::Result<()> {
    self.terminate.store(false, Ordering::Relaxed);
    let waker = mio::Waker::new(registry, token)?;
    let (in_tx, in_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();
    self.in_tx.replace(in_tx);
    self.out_rx.replace(out_rx);
    let session = Arc::clone(&self.session);
    let terminate = Arc::clone(&self.terminate);
    self.thread = Some(std::thread::spawn(move || {
      let mut packet_buffer = VecDeque::new();
      loop {
        if terminate.load(Ordering::Relaxed) {
          return Ok(());
        }
        if let Ok(packet) = session.recv() {
          out_tx
            .send(packet.slice().to_vec())
            .map_err(|err| std::io::Error::new(ErrorKind::ConnectionAborted, err))?;
          if interests.is_readable() {
            waker.wake()?;
          }
        }
        for packet in in_rx.try_iter() {
          if packet.len() > 0xFFFF {
            continue;
          }
          if let Some(mut packet_send) = packet
            .len()
            .try_into()
            .ok()
            .and_then(|len| session.allocate(len).ok())
          {
            packet_send.mut_slice().copy_from_slice(&packet);
            packet_send.send();
            drop(out_tx.send(packet));
            if interests.is_readable() {
              waker.wake()?;
            }
          } else {
            packet_buffer.push_back(packet);
          }
        }
        if let Some(packet) = packet_buffer.pop_front() {
          if let Some(mut packet_send) = packet
            .len()
            .try_into()
            .ok()
            .and_then(|len| session.allocate(len).ok())
          {
            packet_send.mut_slice().copy_from_slice(&packet);
            packet_send.send();
          } else {
            packet_buffer.push_back(packet);
          }
        }
        if interests.is_writable() && packet_buffer.is_empty() {
          waker.wake()?;
        }
      }
    }));
    Ok(())
  }

  fn reregister(
    &mut self,
    registry: &mio::Registry,
    token: mio::Token,
    interests: mio::Interest,
  ) -> std::io::Result<()> {
    self.deregister(registry)?;
    self.register(registry, token, interests)
  }

  fn deregister(&mut self, _: &mio::Registry) -> std::io::Result<()> {
    self.terminate.store(true, Ordering::Relaxed);
    std::mem::replace(&mut self.thread, None)
      .ok_or(std::io::Error::new(
        ErrorKind::Other,
        "Failed precondition: not registered yet",
      ))?
      .join()
      .unwrap()
  }
}
