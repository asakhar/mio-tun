// use std::os::windows::{prelude::FromRawHandle, raw::HANDLE};

// pub use wintun2::*;

// use mio::windows::NamedPipe;

// struct ReadEvent(Option<NamedPipe>);
// impl From<HANDLE> for ReadEvent {
//   fn from(value: HANDLE) -> Self {
//     Self(Some(unsafe { NamedPipe::from_raw_handle(value) }))
//   }
// }

// pub struct MioSession {
//   session: Session,
//   read_event: ReadEvent,
// }

// impl MioSession {
//   pub fn allocate(&self, size: IpPacketSize) -> Result<SendPacket, AllocatePacketError> {
//     self.session.allocate(size)
//   }
//   pub fn recv(&self) -> Result<RecvPacket, ReceivePacketError> {
//     self.session.recv()
//   }
//   pub fn into_inner(mut self) -> Session {
//     std::mem::forget(self.read_event.0.take());
//     self.session
//   }
// }

// impl Drop for ReadEvent {
//   fn drop(&mut self) {
//     std::mem::forget(self.0.take())
//   }
// }

// impl TryFrom<Session> for MioSession {
//   type Error = wintun2::WintunError;
//   fn try_from(session: Session) -> Result<Self, Self::Error> {
//     let handle = session.get_read_wait_event()?;
//     let read_event = ReadEvent::from(handle);
//     Ok(Self {
//       session,
//       read_event,
//     })
//   }
// }

// impl mio::event::Source for MioSession {
//   fn register(
//     &mut self,
//     registry: &mio::Registry,
//     token: mio::Token,
//     interests: mio::Interest,
//   ) -> std::io::Result<()> {
//     registry.register(self.read_event.0.as_mut().unwrap(), token, interests)
//   }

//   fn reregister(
//     &mut self,
//     registry: &mio::Registry,
//     token: mio::Token,
//     interests: mio::Interest,
//   ) -> std::io::Result<()> {
//     registry.reregister(self.read_event.0.as_mut().unwrap(), token, interests)
//   }

//   fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
//     registry.deregister(self.read_event.0.as_mut().unwrap())
//   }
// }

// #[cfg(test)]
// mod tests {
//     use wintun2::{Adapter, RingCapacity};

//     use crate::MioSession;

//   #[test]
//   fn create_session() {
//     let mut adapter = Adapter::create("name", "tun", None).unwrap();
//     let session = adapter.session(RingCapacity::max()).unwrap();
//     let mut session: MioSession = session.try_into().unwrap();
//     let mut poll = mio::Poll::new().unwrap();
//     let mut events = mio::Events::with_capacity(1000);
//     poll.registry().register(&mut session, mio::Token(0), mio::Interest::READABLE).unwrap();
//     poll.poll(&mut events, None).unwrap();
//     session.recv().unwrap();
//   }
// }

pub struct Tun {
  session: Pin<Arc<Session>>,
  adapter: Pin<Arc<Mutex<Adapter>>>,
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
  pub fn from_adapter(adapter: Arc<Adapter>) -> std::io::Result<Self> {
    let session = adapter
      .start_session(wintun::MAX_RING_CAPACITY)
      .map_err(|err| std::io::Error::new(ErrorKind::Other, format!("{err}")))?;
    let session = Arc::new(session);
    Ok(Self {
      session,
      adapter,
      in_tx: None,
      out_rx: None,
      thread: None,
      terminate: Arc::new(AtomicBool::new(true)),
    })
  }
  pub fn new_with_path(
    path: impl AsRef<Path>,
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    let (session, adapter) = session_with_path(path, name, pool)?;
    set_ip_address(&adapter, ip, mask)?;
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
    Self::new_with_path(get_tmp_path(), name, pool, ip, mask)
  }
  pub fn new_alongside(
    name: impl AsRef<str>,
    pool: impl AsRef<str>,
    ip: Ipv4Addr,
    mask: u8,
  ) -> std::io::Result<Self> {
    Self::new_with_path(ALOGNSIDE_PATH, name, pool, ip, mask)
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
  pub fn adapter(&self) -> &Arc<Adapter> {
    &self.adapter
  }
}

impl Drop for Tun {
  fn drop(&mut self) {
    self.terminate.store(true, Ordering::Relaxed);
    if let Some(thread) = std::mem::replace(&mut self.thread, None) {
      drop(thread.join());
    }
    self.session.shutdown();
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
        if let Some(packet) = session.try_receive().map_err(|_| {
          std::io::Error::new(
            ErrorKind::ConnectionAborted,
            "Failed to receive packet from session",
          )
        })? {
          out_tx
            .send(packet.bytes().to_vec())
            .map_err(|err| std::io::Error::new(ErrorKind::ConnectionAborted, err))?;
          if interests.is_readable() {
            waker.wake()?;
          }
        }
        for packet in in_rx.try_iter() {
          if packet.len() > 0xFFFF {
            continue;
          }
          if let Ok(mut packet_send) = session.allocate_send_packet(packet.len() as u16) {
            packet_send.bytes_mut().copy_from_slice(&packet);
            session.send_packet(packet_send);
          } else {
            packet_buffer.push_back(packet);
          }
        }
        if let Some(packet) = packet_buffer.pop_front() {
          if let Ok(mut packet_send) = session.allocate_send_packet(packet.len() as u16) {
            packet_send.bytes_mut().copy_from_slice(&packet);
            session.send_packet(packet_send);
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
