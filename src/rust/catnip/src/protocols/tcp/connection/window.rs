use super::super::segment::{TcpSegment, MAX_MSS, MIN_MSS};
use crate::{io::IoVec, prelude::*};
use std::{
    cmp::min,
    collections::VecDeque,
    convert::TryFrom,
    num::Wrapping,
    rc::Rc,
    time::{Duration, Instant},
};

pub struct UnacknowledgedTcpSegment {
    last_transmission_timestamp: Instant,
    payload: Rc<Vec<u8>>,
    retries: usize,
    seq_num: Wrapping<u32>,
}

impl UnacknowledgedTcpSegment {
    pub fn new(
        payload: Vec<u8>,
        seq_num: Wrapping<u32>,
        now: Instant,
    ) -> UnacknowledgedTcpSegment {
        UnacknowledgedTcpSegment {
            last_transmission_timestamp: now,
            payload: Rc::new(payload),
            seq_num,
            retries: 0,
        }
    }

    pub fn get_last_transmission_timestamp(&self) -> Instant {
        self.last_transmission_timestamp
    }

    pub fn set_last_transmission_timestamp(&mut self, timestamp: Instant) {
        self.last_transmission_timestamp = timestamp;
    }

    pub fn get_payload(&self) -> &Rc<Vec<u8>> {
        &self.payload
    }

    pub fn get_retries(&self) -> usize {
        self.retries
    }

    pub fn add_retry(&mut self) {
        self.retries += 1;
    }
}

pub struct TcpSendWindow {
    bytes_unacknowledged: usize,
    last_seq_num_transmitted: Wrapping<u32>,
    mss: usize,
    remote_receive_window_size: usize,
    smallest_unacknowledged_seq_num: Wrapping<u32>,
    unacknowledged_segments: VecDeque<UnacknowledgedTcpSegment>,
    unsent_segment_offset: usize,
    unsent_segments: VecDeque<Vec<u8>>,
}

impl TcpSendWindow {
    pub fn new(
        local_isn: Wrapping<u32>,
        advertised_mss: usize,
    ) -> TcpSendWindow {
        TcpSendWindow {
            bytes_unacknowledged: 0,
            last_seq_num_transmitted: local_isn,
            mss: advertised_mss,
            remote_receive_window_size: 0,
            smallest_unacknowledged_seq_num: local_isn,
            unacknowledged_segments: VecDeque::new(),
            unsent_segment_offset: 0,
            unsent_segments: VecDeque::new(),
        }
    }

    pub fn get_expected_remote_receive_window_size(&self) -> usize {
        self.remote_receive_window_size - self.bytes_unacknowledged
    }

    pub fn set_remote_receive_window_size(&mut self, size: usize) {
        self.remote_receive_window_size = size;
    }

    pub fn get_last_seq_num(&self) -> Wrapping<u32> {
        self.last_seq_num_transmitted
    }

    pub fn incr_seq_num(&mut self) {
        self.smallest_unacknowledged_seq_num += Wrapping(1);
        self.last_seq_num_transmitted += Wrapping(1);
    }

    pub fn get_mss(&self) -> usize {
        self.mss
    }

    pub fn negotiate_mss(&mut self, remote_mss: Option<usize>) -> Result<()> {
        // from [TCP/IP Illustrated](https://learning.oreilly.com/library/view/tcpip-illustrated-volume/9780132808200/ch13.html):
        // > If no MSS option is provided, a default value of 536 bytes is
        // > used.
        let remote_mss = remote_mss.unwrap_or(MIN_MSS);
        if remote_mss < MIN_MSS {
            return Err(Fail::OutOfRange {
                details: "remote MSS is less than allowed minimum",
            });
        }

        if remote_mss > MAX_MSS {
            return Err(Fail::OutOfRange {
                details: "remote MSS exceeds allowed maximum",
            });
        }

        self.mss = min(self.mss, remote_mss);
        info!("mss = {}", self.mss);
        Ok(())
    }

    pub fn push(&mut self, iovec: IoVec) {
        self.unsent_segments.extend(iovec);
    }

    pub fn acknowledge(
        &mut self,
        ack_num: Wrapping<u32>,
    ) -> Result<Vec<UnacknowledgedTcpSegment>> {
        trace!("TcpSendWindow::acknowledge({:?})", ack_num);
        debug!(
            "smallest_unacknowledged_seq_num = {:?}",
            self.smallest_unacknowledged_seq_num
        );

        let bytes_acknowledged =
            (ack_num - self.smallest_unacknowledged_seq_num).0 as usize;

        if 0 == bytes_acknowledged {
            return Ok(vec![]);
        }

        if bytes_acknowledged > self.bytes_unacknowledged {
            error!(
                "acknowledgment is outside of send window scope ({} > {})",
                bytes_acknowledged, self.bytes_unacknowledged
            );
            return Err(Fail::Ignored {
                details: "acknowledgement is outside of send window scope",
            });
        }

        let mut n = 0;
        let mut acked_segment_count = 0;
        for segment in &self.unacknowledged_segments {
            n += segment.payload.len();
            acked_segment_count += 1;

            if n >= bytes_acknowledged {
                break;
            }
        }

        if n != bytes_acknowledged {
            return Err(Fail::Ignored {
                details: "acknowledgement did not fall on a segment boundary",
            });
        }

        let mut acked_segments = Vec::new();
        for _ in 0..acked_segment_count {
            let segment = self.unacknowledged_segments.pop_front().unwrap();
            acked_segments.push(segment);
        }

        self.bytes_unacknowledged -= bytes_acknowledged;
        self.smallest_unacknowledged_seq_num +=
            Wrapping(u32::try_from(bytes_acknowledged).unwrap());
        Ok(acked_segments)
    }

    pub fn get_next_transmittable_payload(
        &mut self,
        optional_byte_count: Option<usize>,
        now: Instant,
    ) -> Option<Rc<Vec<u8>>> {
        trace!("TcpSendWindow::get_next_transmittable_payload()");
        if self.unsent_segments.is_empty() {
            None
        } else {
            let expected_remote_receive_window_size =
                self.get_expected_remote_receive_window_size();
            debug!(
                "expected_remote_receive_window_size = {}",
                expected_remote_receive_window_size
            );
            if self.get_expected_remote_receive_window_size() == 0 {
                return None;
            }

            let next_unsent_segment =
                self.unsent_segments.front_mut().unwrap();
            let bytes_remaining =
                next_unsent_segment.len() - self.unsent_segment_offset;
            let mss = self.mss;
            let byte_count = optional_byte_count.unwrap_or_else(|| {
                min(
                    min(mss, bytes_remaining),
                    expected_remote_receive_window_size,
                )
            });

            let payload = if self.unsent_segment_offset == 0
                && byte_count == next_unsent_segment.len()
            {
                self.unsent_segments.pop_front().unwrap()
            } else {
                let range_end = self.unsent_segment_offset + byte_count;
                let payload = next_unsent_segment
                    [self.unsent_segment_offset..range_end]
                    .to_vec();
                if range_end == next_unsent_segment.len() {
                    self.unsent_segment_offset = 0;
                    let _ = self.unsent_segments.pop_front().unwrap();
                } else {
                    self.unsent_segment_offset += byte_count;
                }

                payload
            };

            self.last_seq_num_transmitted = self
                .smallest_unacknowledged_seq_num
                + Wrapping(u32::try_from(self.bytes_unacknowledged).unwrap());
            self.bytes_unacknowledged += payload.len();
            let segment = UnacknowledgedTcpSegment::new(
                payload,
                self.last_seq_num_transmitted,
                now,
            );
            self.unacknowledged_segments.push_back(segment);
            self.unacknowledged_segments
                .back()
                .map(|s| s.get_payload().clone())
        }
    }

    pub fn get_unacknowledged_segment_age(
        &self,
        now: Instant,
    ) -> Option<Duration> {
        self.unacknowledged_segments
            .front()
            .map(|s| now - s.get_last_transmission_timestamp())
    }

    pub fn get_retransmissions(
        &mut self,
        now: Instant,
    ) -> VecDeque<Rc<Vec<u8>>> {
        for segment in &mut self.unacknowledged_segments {
            segment.set_last_transmission_timestamp(now);
            segment.add_retry();
        }

        self.unacknowledged_segments
            .iter()
            .map(|s| s.get_payload().clone())
            .collect()
    }
}

pub struct TcpReceiveWindow {
    ack_num: Option<Wrapping<u32>>,
    bytes_unread: usize,
    max_window_size: usize,
    unread_segments: VecDeque<TcpSegment>,
}

impl TcpReceiveWindow {
    pub fn new(max_window_size: usize) -> TcpReceiveWindow {
        TcpReceiveWindow {
            max_window_size,
            ack_num: None,
            bytes_unread: 0,
            unread_segments: VecDeque::new(),
        }
    }

    pub fn window_size(&self) -> usize {
        self.max_window_size - self.bytes_unread
    }

    pub fn ack_num(&self) -> Option<Wrapping<u32>> {
        self.ack_num
    }

    pub fn is_empty(&self) -> bool {
        self.bytes_unread == 0
    }

    pub fn remote_isn(&mut self, value: Wrapping<u32>) {
        assert!(self.ack_num.is_none());
        self.ack_num = Some(value + Wrapping(1));
    }

    pub fn pop(&mut self) -> IoVec {
        let mut iovec = IoVec::new();
        while let Some(segment) = self.unread_segments.pop_front() {
            let payload = Rc::try_unwrap(segment.payload).unwrap();
            iovec.push_segment(payload);
        }

        self.bytes_unread = 0;
        iovec
    }

    pub fn push(&mut self, segment: TcpSegment) -> Result<()> {
        trace!("TcpReceiveWindow::receive({:?})", segment);
        let bytes_unread = self.bytes_unread + segment.payload.len();
        if bytes_unread > self.max_window_size {
            return Err(Fail::ResourceExhausted {
                details: "receive window is full",
            });
        }

        let ack_num = Some(
            self.ack_num.unwrap()
                + Wrapping(u32::try_from(segment.payload.len()).unwrap()),
        );
        debug!("ack_num: {:?} -> {:?}", self.ack_num, ack_num);
        self.ack_num = ack_num;
        self.unread_segments.push_back(segment);
        self.bytes_unread = bytes_unread;
        Ok(())
    }
}
