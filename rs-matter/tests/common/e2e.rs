/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroU8;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use embassy_futures::select::{select3, select4};

use embassy_sync::zerocopy_channel::{Channel, Receiver, Sender};

use rs_matter::acl::{AclEntry, AuthMode};
use rs_matter::crypto::{test_only_crypto, CanonAeadKeyRef, Crypto};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::{DataModel, Privilege};
use rs_matter::error::Error;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::persist::{DummyKvBlobStore, KvBlobStore};
use rs_matter::respond::{ExchangeHandler, Responder};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::network::{
    Address, NetworkReceive, NetworkSend, NoNetwork, MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
};
use rs_matter::transport::packet::PacketHdr;
use rs_matter::transport::session::{NocCatIds, ReservedSession, SessionMode};
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::{ParseBuf, ReadBuf, WriteBuf};
use rs_matter::utils::sync::blocking::raw::MatterRawMutex;
use rs_matter::{Matter, MATTER_PORT};

pub mod im;
pub mod test;
pub mod tlv;

pub const TEST_PEER_ID: u64 = 445566;

const TEST_PEER_ADDR: Address =
    Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

/// Create a new runner with default category IDs.
pub fn new_default_runner() -> E2eRunner<impl Crypto> {
    new_runner(NocCatIds::default())
}

/// Create a new runner with the given category IDs.
pub fn new_runner(cat_ids: NocCatIds) -> E2eRunner<impl Crypto> {
    E2eRunner::new(test_only_crypto(), cat_ids)
}

/// Create a new runner with default category IDs whose device-under-test
/// serves the given `BasicInfoConfig` instead of `TEST_DEV_DET`.
///
/// For tests exercising configuration-derived behavior (e.g. the
/// `BasicInfoConfig` factory defaults for `Location` / `DeviceLocation`).
// The `common` module is shared by several test binaries; this helper is
// used only by `data_model_tests`.
#[allow(unused)]
pub fn new_default_runner_with_dev_det(
    dev_det: &'static BasicInfoConfig<'static>,
) -> E2eRunner<impl Crypto> {
    E2eRunner::new_with_dev_det(test_only_crypto(), NocCatIds::default(), dev_det)
}

// Set large enough that we can store more events than fit in an ethernet frame, so we can test "long reads"
pub const E2E_EVENTS_BUF_SIZE: usize = 1024 * 4;

/// A test runner for end-to-end tests.
///
/// The runner works by instantiating two `Matter` instances, one for the local node and one for the
/// remote node which is being tested. The instances are connected over a fake UDP network.
///
/// The runner then pre-set a single session between the two nodes and runs all tests in the context
/// of a single exchange per test run.
///
/// All transport-related state is reset between test runs.
pub struct E2eRunner<C> {
    pub matter: Matter<'static>,
    matter_client: Matter<'static>,
    crypto: C,
    buffers: MatterBuffers,
    pub state: InteractionModelState<DummyNetworks, 3, E2E_EVENTS_BUF_SIZE>,
    cat_ids: NocCatIds,
}

impl<C: Crypto> E2eRunner<C> {
    const ADDR: Address = TEST_PEER_ADDR;

    /// The ID of the local Matter instance
    pub const PEER_ID: u64 = TEST_PEER_ID;

    /// The ID of the remote (tested) Matter instance
    pub const REMOTE_PEER_ID: u64 = 123456;

    /// Create a new runner with the given category IDs.
    pub fn new(crypto: C, cat_ids: NocCatIds) -> E2eRunner<C> {
        Self::new_with_dev_det(crypto, cat_ids, &TEST_DEV_DET)
    }

    /// Like [`Self::new`], but the device-under-test `Matter` instance
    /// serves the given `BasicInfoConfig` instead of `TEST_DEV_DET`.
    pub fn new_with_dev_det(
        crypto: C,
        cat_ids: NocCatIds,
        dev_det: &'static BasicInfoConfig<'static>,
    ) -> E2eRunner<C> {
        E2eRunner {
            matter: Self::new_matter(dev_det),
            matter_client: Self::new_matter(&TEST_DEV_DET),
            crypto,
            buffers: MatterBuffers::new(),
            state: InteractionModelState::new(DummyNetworks),
            cat_ids,
        }
    }

    /// Initialize the local and remote (tested) Matter instances
    /// that the runner owns
    pub fn init(&self) -> Result<(), Error> {
        Self::init_matter(
            &self.matter,
            &self.crypto,
            Self::REMOTE_PEER_ID,
            Self::PEER_ID,
            &self.cat_ids,
        )?;

        Self::init_matter(
            &self.matter_client,
            &self.crypto,
            Self::PEER_ID,
            Self::REMOTE_PEER_ID,
            &self.cat_ids,
        )
    }

    /// Get the Matter instance for the local node (the test driver).
    pub fn matter_client(&self) -> &Matter<'static> {
        &self.matter_client
    }

    /// Add a default ACL entry to the remote (tested) Matter instance.
    pub fn add_default_acl(&self) {
        // Only allow the standard peer node id of the IM Engine
        let mut default_acl = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
        default_acl.add_subject(Self::PEER_ID).unwrap();
        self.matter.with_state(|state| {
            state
                .fabrics
                .fabric_mut(NonZeroU8::new(1).unwrap())
                .unwrap()
                .acl_add(default_acl)
                .unwrap();
        });
    }

    /// Initiates a new exchange on the local Matter instance
    pub async fn initiate_exchange(&self) -> Result<Exchange<'_>, Error> {
        Exchange::initiate(
            self.matter_client(),
            rs_matter::crypto::test_only_crypto(),
            NonZeroU8::new(1).unwrap(), /*just one fabric in tests*/
            Self::REMOTE_PEER_ID,
        )
        .await
    }

    /// Runs both the local and the remote (tested) Matter instances,
    /// by connecting them with a fake UDP network.
    ///
    /// The remote (tested) Matter instance will run with the provided DM handler.
    ///
    /// The local Matter instance does not have a DM handler as it is only used to
    /// drive the tests (i.e. it does not have any server clusters and such).
    pub async fn run<H>(&self, handler: H) -> Result<(), Error>
    where
        H: DataModel,
    {
        self.run_with(handler, &self.state, DummyKvBlobStore, false)
            .await
    }

    /// Like [`run`](Self::run), but drives the remote (tested) data model over
    /// an explicit [`InteractionModelState`] and key-value store, and optionally
    /// resumes persisted subscriptions before serving traffic.
    ///
    /// This is what makes a reboot testable: run once to establish + persist a
    /// subscription (into a retained `kv`), then run again with a *fresh* state
    /// and `resume = true` over the *same* `kv` to re-hydrate it — the moral
    /// equivalent of the device restarting with its storage intact.
    pub async fn run_with<H, S, K, const NS: usize, const NE: usize>(
        &self,
        handler: H,
        state: &InteractionModelState<S, NS, NE>,
        kv_store: K,
        resume: bool,
    ) -> Result<(), Error>
    where
        H: DataModel,
        S: rs_matter::dm::clusters::net_comm::Networks,
        K: KvBlobStore,
    {
        self.init()?;

        // The e2e fixtures assert exact event queues; the boot-time
        // `BasicInformation::StartUp` emission is covered end-to-end by the
        // chip-tool integration tests (`TC_BINFO_2_2`), so keep it out of the
        // deterministic unit expectations here.
        state.suppress_start_up_event();

        let mut buf1 = [heapless::Vec::new(); 1];
        let mut buf2 = [heapless::Vec::new(); 1];

        let mut pipe1 = NetworkPipe::<MAX_RX_PACKET_SIZE>::new(&mut buf1);
        let mut pipe2 = NetworkPipe::<MAX_TX_PACKET_SIZE>::new(&mut buf2);

        let (send_remote, recv_local) = pipe1.split();
        let (send_local, recv_remote) = pipe2.split();

        let matter_client = &self.matter_client;

        let kv = self.matter.kv(kv_store);

        let dm = InteractionModel::new(
            &self.matter,
            &self.crypto,
            &self.buffers,
            handler,
            &kv,
            state,
        );

        if resume {
            // The moral equivalent of the device rebooting with its storage
            // intact: re-hydrate the IM state, replay the persisted
            // subscriptions and deliver `LifecycleOp::Startup` to the handler.
            dm.startup().await?;
        }

        let responder = Responder::new_default(&dm);

        select4(
            matter_client.run(
                &self.crypto,
                NetworkSendImpl::new(send_local, TEST_PEER_ID, None),
                NetworkReceiveImpl(recv_local),
                NoNetwork,
            ),
            self.matter.run(
                &self.crypto,
                NetworkSendImpl::new(send_remote, 123456, None),
                NetworkReceiveImpl(recv_remote),
                NoNetwork,
            ),
            responder.run::<4>(),
            dm.run(),
        )
        .coalesce()
        .await
    }

    /// Like [`run`](Self::run), but drives a custom [`ExchangeHandler`] on the
    /// remote (tested) instance instead of the Interaction Model data model.
    ///
    /// Useful for exercising non-IM protocols (e.g. BDX) over the established
    /// CASE session: pair it (via `select`) with a client flow that uses
    /// [`initiate_exchange`](Self::initiate_exchange).
    #[allow(dead_code)] // Only used by some of the test binaries that share `common`.
    pub async fn run_responder<H>(&self, handler: H) -> Result<(), Error>
    where
        H: ExchangeHandler,
    {
        self.run_responder_with_packet_observer(handler, None).await
    }

    /// Drive one wire-level BDX cancellation race in the fake CASE network.
    /// The injected reliable Query(1) has no piggyback ACK and is followed by
    /// an independent ACK for the failure StatusReport.
    #[allow(dead_code)]
    pub async fn run_responder_with_late_bdx_query<H>(
        &self,
        handler: H,
        race: &E2eLateBdxQueryRace,
    ) -> Result<(), Error>
    where
        H: ExchangeHandler,
    {
        self.run_responder_with_packet_observer(handler, Some(race))
            .await
    }

    async fn run_responder_with_packet_observer<H>(
        &self,
        handler: H,
        race: Option<&E2eLateBdxQueryRace>,
    ) -> Result<(), Error>
    where
        H: ExchangeHandler,
    {
        self.init()?;

        let mut buf1 = [heapless::Vec::new(); 1];
        let mut buf2 = [heapless::Vec::new(); 1];

        let mut pipe1 = NetworkPipe::<MAX_RX_PACKET_SIZE>::new(&mut buf1);
        let mut pipe2 = NetworkPipe::<MAX_TX_PACKET_SIZE>::new(&mut buf2);

        let (send_remote, recv_local) = pipe1.split();
        let (send_local, recv_remote) = pipe2.split();

        let matter_client = &self.matter_client;

        let responder = Responder::new("test-responder", handler, &self.matter, 0);

        select3(
            matter_client.run(
                &self.crypto,
                NetworkSendImpl::new(send_local, TEST_PEER_ID, race),
                NetworkReceiveImpl(recv_local),
                NoNetwork,
            ),
            self.matter.run(
                &self.crypto,
                NetworkSendImpl::new(send_remote, 123456, race),
                NetworkReceiveImpl(recv_remote),
                NoNetwork,
            ),
            responder.run::<4>(),
        )
        .coalesce()
        .await
    }

    fn new_matter(dev_det: &'static BasicInfoConfig<'static>) -> Matter<'static> {
        #[cfg(not(feature = "std"))]
        use rs_matter::utils::rand::dummy_rand as rand;

        let matter = Matter::new(dev_det, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

        matter.with_state(|state| {
            state.fabrics.add_with_post_init(|_| Ok(())).unwrap();
        });

        matter
    }

    fn init_matter(
        matter: &Matter,
        crypto: impl Crypto,
        local_nodeid: u64,
        remote_nodeid: u64,
        cat_ids: &NocCatIds,
    ) -> Result<(), Error> {
        matter.reset_transport()?;

        let mut session = ReservedSession::reserve_now(matter, crypto)?;

        session.update(
            local_nodeid,
            remote_nodeid,
            1,
            1,
            Self::ADDR,
            SessionMode::Case {
                fab_idx: NonZeroU8::new(1).unwrap(),
                cat_ids: *cat_ids,
            },
            None,
            None,
            None,
            None,
        )?;

        session.complete();

        Ok(())
    }
}

type NetworkPipe<'a, const N: usize> = Channel<'a, MatterRawMutex, heapless::Vec<u8, N>>;

struct NetworkReceiveImpl<'a, const N: usize>(Receiver<'a, MatterRawMutex, heapless::Vec<u8, N>>);

const E2E_CASE_KEY: CanonAeadKeyRef<'static> = CanonAeadKeyRef::new(&[0; 16]);

/// Coordinate a same-exchange BDX Query(1) arriving after cancellation starts
/// and an independent StatusReport ACK queued behind it.
pub struct E2eLateBdxQueryRace {
    armed: AtomicBool,
    status_report_sent: AtomicBool,
    status_report_counter: AtomicU32,
    status_report_attempts: AtomicUsize,
    status_report_wire_hash: AtomicU64,
    status_report_wire_len: AtomicUsize,
    status_report_retries_identical: AtomicBool,
    status_report_retried: AtomicBool,
    status_report_reliable: AtomicBool,
    status_report_status: AtomicU32,
    exchange_id: AtomicUsize,
    query_counter: AtomicU32,
    query_ack_counter: AtomicU32,
    query_injected: AtomicBool,
    query_acknowledged: AtomicBool,
    block_one_sent: AtomicBool,
    block_eof_one_sent: AtomicBool,
}

// This shared transport fixture is compiled into every integration test, but
// its observations are intentionally consumed only by the BDX integration test.
#[allow(dead_code)]
impl E2eLateBdxQueryRace {
    pub fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            status_report_sent: AtomicBool::new(false),
            status_report_counter: AtomicU32::new(0),
            status_report_attempts: AtomicUsize::new(0),
            status_report_wire_hash: AtomicU64::new(0),
            status_report_wire_len: AtomicUsize::new(0),
            status_report_retries_identical: AtomicBool::new(true),
            status_report_retried: AtomicBool::new(false),
            status_report_reliable: AtomicBool::new(false),
            status_report_status: AtomicU32::new(0),
            exchange_id: AtomicUsize::new(usize::MAX),
            query_counter: AtomicU32::new(0),
            query_ack_counter: AtomicU32::new(0),
            query_injected: AtomicBool::new(false),
            query_acknowledged: AtomicBool::new(false),
            block_one_sent: AtomicBool::new(false),
            block_eof_one_sent: AtomicBool::new(false),
        }
    }

    pub fn arm_query(&self) {
        self.armed.store(true, Ordering::Release);
    }

    pub fn query_injected(&self) -> bool {
        self.query_injected.load(Ordering::Acquire)
    }

    pub fn status_report_sent(&self) -> bool {
        self.status_report_sent.load(Ordering::Acquire)
    }

    pub fn status_report_counter(&self) -> u32 {
        self.status_report_counter.load(Ordering::Acquire)
    }

    pub fn status_report_retried(&self) -> bool {
        self.status_report_retried.load(Ordering::Acquire)
    }

    pub fn status_report_retries_identical(&self) -> bool {
        self.status_report_retries_identical.load(Ordering::Acquire)
    }

    pub fn status_report_attempts(&self) -> usize {
        self.status_report_attempts.load(Ordering::Acquire)
    }

    pub fn status_report_reliable(&self) -> bool {
        self.status_report_reliable.load(Ordering::Acquire)
    }

    pub fn status_report_status(&self) -> u32 {
        self.status_report_status.load(Ordering::Acquire)
    }

    pub fn query_ack_counter(&self) -> u32 {
        self.query_ack_counter.load(Ordering::Acquire)
    }

    pub fn block_one_sent(&self) -> bool {
        self.block_one_sent.load(Ordering::Acquire)
    }

    pub fn query_acknowledged(&self) -> bool {
        self.query_acknowledged.load(Ordering::Acquire)
    }

    pub fn block_eof_one_sent(&self) -> bool {
        self.block_eof_one_sent.load(Ordering::Acquire)
    }
}

impl Default for E2eLateBdxQueryRace {
    fn default() -> Self {
        Self::new()
    }
}

struct NetworkSendImpl<'p, 'r, const N: usize> {
    sender: Sender<'p, MatterRawMutex, heapless::Vec<u8, N>>,
    local_node_id: u64,
    race: Option<&'r E2eLateBdxQueryRace>,
}

impl<'p, 'r, const N: usize> NetworkSendImpl<'p, 'r, N> {
    fn new(
        sender: Sender<'p, MatterRawMutex, heapless::Vec<u8, N>>,
        local_node_id: u64,
        race: Option<&'r E2eLateBdxQueryRace>,
    ) -> Self {
        Self {
            sender,
            local_node_id,
            race,
        }
    }

    async fn send_packet(&mut self, data: &[u8]) {
        let vec = self.sender.send().await;
        vec.clear();
        vec.extend_from_slice(data).unwrap();
        self.sender.send_done();
    }

    fn observe_server_packet(&self, data: &[u8], race: &E2eLateBdxQueryRace) -> Result<(), Error> {
        if self.local_node_id != 123456 {
            return Ok(());
        }

        let (header, payload) = decode_e2e_packet(data, 123456)?;
        if header.proto.proto_id == rs_matter::sc::PROTO_ID_SECURE_CHANNEL
            && header.proto.proto_opcode == rs_matter::sc::OpCode::StatusReport as u8
        {
            let mut rb = ReadBuf::new(payload.as_slice());
            let report = rs_matter::sc::StatusReport::read(&mut rb)?;
            if report.proto_id == rs_matter::bdx::PROTO_ID_BDX as u32 {
                race.exchange_id
                    .store(header.proto.exch_id as usize, Ordering::Release);
                race.status_report_counter
                    .store(header.plain.ctr, Ordering::Release);
                race.status_report_reliable
                    .store(header.proto.is_reliable(), Ordering::Release);
                race.status_report_status
                    .store(report.proto_code as u32, Ordering::Release);
                let attempt = race.status_report_attempts.fetch_add(1, Ordering::AcqRel);
                let wire_hash = packet_hash(data);
                if attempt == 0 {
                    race.status_report_wire_hash
                        .store(wire_hash, Ordering::Release);
                    race.status_report_wire_len
                        .store(data.len(), Ordering::Release);
                } else {
                    let identical = wire_hash
                        == race.status_report_wire_hash.load(Ordering::Acquire)
                        && data.len() == race.status_report_wire_len.load(Ordering::Acquire);
                    if !identical {
                        race.status_report_retries_identical
                            .store(false, Ordering::Release);
                    }
                    // Release the fake peer's held ACK once the retry has
                    // entered the network send path. Publishing it can await
                    // the client freeing its one-packet RX channel.
                    race.status_report_retried.store(true, Ordering::Release);
                }
            }
        } else if header.proto.proto_id == rs_matter::sc::PROTO_ID_SECURE_CHANNEL
            && header.proto.proto_opcode == rs_matter::sc::OpCode::MRPStandAloneAck as u8
            && header.proto.get_ack() == Some(race.query_counter.load(Ordering::Acquire))
            && header.proto.exch_id as usize == race.exchange_id.load(Ordering::Acquire)
        {
            race.query_ack_counter
                .store(header.plain.ctr, Ordering::Release);
            race.query_acknowledged.store(true, Ordering::Release);
        } else if header.proto.proto_id == rs_matter::bdx::PROTO_ID_BDX
            && header.proto.proto_opcode == rs_matter::bdx::OpCode::Block as u8
        {
            let block = rs_matter::bdx::Block::parse(&payload)?;
            if block.block_counter == 1 {
                race.block_one_sent.store(true, Ordering::Release);
            }
        } else if header.proto.proto_id == rs_matter::bdx::PROTO_ID_BDX
            && header.proto.proto_opcode == rs_matter::bdx::OpCode::BlockEof as u8
        {
            let block = rs_matter::bdx::Block::parse(&payload)?;
            if block.block_counter == 1 {
                race.block_eof_one_sent.store(true, Ordering::Release);
            }
        }

        Ok(())
    }
}

impl<const N: usize> NetworkSend for NetworkSendImpl<'_, '_, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        let Some(race) = self.race else {
            self.send_packet(data).await;
            return Ok(());
        };

        let is_server = self.local_node_id == 123456;
        if !race.armed.load(Ordering::Acquire) {
            self.observe_server_packet(data, race)?;
            self.send_packet(data).await;
            if is_server && is_bdx_abort_report(data)? {
                race.status_report_sent.store(true, Ordering::Release);
            }
            return Ok(());
        }

        if is_server {
            self.observe_server_packet(data, race)?;
            if is_bdx_abort_report(data)? {
                // The fake peer consumes the report at the wire boundary and
                // delays its ACK until the retry. Do not occupy the client
                // Matter RX buffer ahead of the Query ACK being tested.
                race.status_report_sent.store(true, Ordering::Release);
                if race.status_report_attempts() > 1 {
                    race.status_report_retried.store(true, Ordering::Release);
                }
                return Ok(());
            }
            self.send_packet(data).await;
            return Ok(());
        }

        let (mut header, payload) = decode_e2e_packet(data, TEST_PEER_ID)?;
        if header.proto.proto_id == rs_matter::sc::PROTO_ID_SECURE_CHANNEL
            && header.proto.proto_opcode == rs_matter::sc::OpCode::MRPStandAloneAck as u8
            && header.proto.get_ack() == Some(race.status_report_counter.load(Ordering::Acquire))
            && header.proto.exch_id as usize == race.exchange_id.load(Ordering::Acquire)
        {
            // The test injects this ACK after observing a report retry.
            return Ok(());
        }

        if header.proto.proto_id != rs_matter::bdx::PROTO_ID_BDX
            || header.proto.proto_opcode != rs_matter::bdx::OpCode::BlockQuery as u8
            || header.proto.get_vendor().is_some()
        {
            self.send_packet(data).await;
            return Ok(());
        }

        let query = rs_matter::bdx::BlockQuery::parse(&payload)?;
        assert_eq!(query.block_counter, 1, "late packet must be BDX Query(1)");
        assert!(
            header.proto.is_reliable(),
            "BlockQuery must remain reliable"
        );
        assert!(
            header.proto.get_ack().is_some(),
            "the e2e client fixture must expose its previously sent Block(0) ACK"
        );
        race.query_counter
            .store(header.plain.ctr, Ordering::Release);

        while !race.status_report_sent.load(Ordering::Acquire) {
            core::future::poll_fn(|cx| {
                if race.status_report_sent.load(Ordering::Acquire) {
                    core::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    core::task::Poll::Pending
                }
            })
            .await;
        }

        assert_eq!(
            header.proto.exch_id as usize,
            race.exchange_id.load(Ordering::Acquire),
            "late query and StatusReport must use the same exchange"
        );
        header.proto.set_ack(None);

        let query_packet = encode_e2e_packet(&header, &payload, TEST_PEER_ID)?;
        self.send_packet(&query_packet).await;
        race.query_injected.store(true, Ordering::Release);

        while !race.status_report_retried.load(Ordering::Acquire) {
            core::future::poll_fn(|cx| {
                if race.status_report_retried.load(Ordering::Acquire) {
                    core::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    core::task::Poll::Pending
                }
            })
            .await;
        }

        // Send the StatusReport ACK only after its first retry entered the wire.
        // FIFO leaves the ACK behind Query(1) in the server's single RX buffer.
        let mut ack_header = header;
        ack_header.plain.ctr = ack_header.plain.ctr.wrapping_add(1);
        ack_header.proto.proto_id = rs_matter::sc::PROTO_ID_SECURE_CHANNEL;
        ack_header.proto.proto_opcode = rs_matter::sc::OpCode::MRPStandAloneAck as u8;
        ack_header.proto.unset_reliable();
        ack_header
            .proto
            .set_ack(Some(race.status_report_counter.load(Ordering::Acquire)));
        let ack_packet = encode_e2e_packet(&ack_header, &[], TEST_PEER_ID)?;
        self.send_packet(&ack_packet).await;

        Ok(())
    }
}

fn packet_hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn decode_e2e_packet(data: &[u8], peer_node_id: u64) -> Result<(PacketHdr, Vec<u8>), Error> {
    let mut packet = data.to_vec();
    let mut pb = ParseBuf::new(&mut packet);
    let mut header = PacketHdr::new();
    header.decode_plain_hdr(&mut pb)?;
    header.decode_remaining(
        test_only_crypto(),
        Some(E2E_CASE_KEY),
        peer_node_id,
        &mut pb,
    )?;
    let (start, end) = pb.slice_range();
    Ok((header, packet[start..end].to_vec()))
}

fn encode_e2e_packet(
    header: &PacketHdr,
    payload: &[u8],
    local_node_id: u64,
) -> Result<Vec<u8>, Error> {
    let mut packet = [0; MAX_TX_PACKET_SIZE];
    let mut wb = WriteBuf::new_with(&mut packet, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);
    wb.append(payload)?;
    header.encode(
        test_only_crypto(),
        Some(E2E_CASE_KEY),
        local_node_id,
        &mut wb,
    )?;
    Ok(wb.as_slice().to_vec())
}

fn is_bdx_abort_report(data: &[u8]) -> Result<bool, Error> {
    let (header, payload) = decode_e2e_packet(data, 123456)?;
    if header.proto.proto_id != rs_matter::sc::PROTO_ID_SECURE_CHANNEL
        || header.proto.proto_opcode != rs_matter::sc::OpCode::StatusReport as u8
    {
        return Ok(false);
    }

    let mut rb = ReadBuf::new(payload.as_slice());
    Ok(rs_matter::sc::StatusReport::read(&mut rb)?.proto_id == rs_matter::bdx::PROTO_ID_BDX as u32)
}

impl<const N: usize> NetworkReceive for NetworkReceiveImpl<'_, N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((len, TEST_PEER_ADDR))
    }
}
