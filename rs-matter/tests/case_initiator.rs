#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::future::Future;
use rs_matter::cert::{gen::VALID_FOREVER, CertRef, MAX_CERT_TLV_AND_ASN1_LEN};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonAeadKeyRef, CanonPkcSecretKey, Crypto, Rng, SecretKey,
    SigningSecretKey, AEAD_CANON_KEY_LEN,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::onboard::{cac::RcacGenerator, noc::NocGenerator};

use rs_matter::respond::{ExchangeHandler, Responder};
use rs_matter::sc::case::initiator::{CaseInitiator, CasePeerVerifier, ExpectedPeerIdentity};
use rs_matter::sc::case::{CasePeerIdentity, CaseResponder};
use rs_matter::sc::OpCode;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::Matter;

use crate::common::{
    create_localhost_socket_pair, init_env_logger, run_device_controller, run_with_transport,
};

const FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 100;
const DEVICE_NODE_ID: u64 = 200;

struct AcceptExpectedPeer;

impl<C: Crypto> CasePeerVerifier<C> for AcceptExpectedPeer {
    fn verify_chain(
        &self,
        _crypto: &C,
        root_ca: &[u8],
        expected: ExpectedPeerIdentity,
        noc: &CertRef<'_>,
        _icac: Option<&CertRef<'_>>,
    ) -> Result<(), Error> {
        if root_ca.is_empty()
            || expected.fabric_id() != FABRIC_ID
            || expected.node_id() != DEVICE_NODE_ID
            || noc.get_fabric_id()? != expected.fabric_id()
            || noc.get_node_id()? != expected.node_id()
        {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(())
    }
}

struct CaseIdentityHandler<'a, C> {
    crypto: &'a C,
    peers: async_channel::Sender<CasePeerIdentity>,
}

impl<C: Crypto> ExchangeHandler for CaseIdentityHandler<'_, C> {
    fn handle(&self, mut exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        async move {
            exchange.recv_fetch().await?;
            if exchange.rx()?.meta().opcode::<OpCode>()? == OpCode::CASESigma1 {
                if let Some(peer) = CaseResponder::new(self.crypto)
                    .handle_with_identity(exchange)
                    .await?
                {
                    let _ = self.peers.send(peer).await;
                }
            }
            Ok(())
        }
    }
}
#[test]
fn case_initiator_authenticates_peer_and_owns_session() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let crypto = test_only_crypto();
        let mut rcac_buf = [0; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
        let (rcac_privkey, rcac) = rcac_gen
            .generate(&crypto, FABRIC_ID, VALID_FOREVER)
            .unwrap();
        let mut noc_buf = [0; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut noc_gen =
            NocGenerator::create(rcac_privkey.reference(), rcac, &[], &mut noc_buf).unwrap();

        let mut ipk_bytes = [0; AEAD_CANON_KEY_LEN];
        crypto.rand().unwrap().fill_bytes(&mut ipk_bytes);
        let mut ipk = CanonAeadKey::new();
        ipk.load_from_array(&ipk_bytes);
        let ipk_ref: CanonAeadKeyRef<'_> = ipk.reference();

        let controller_key = crypto.generate_secret_key().unwrap();
        let mut controller_csr_buf = [0; 256];
        let controller_csr = controller_key.csr(&mut controller_csr_buf).unwrap();
        let mut controller_key_canon = CanonPkcSecretKey::new();
        controller_key
            .write_canon(&mut controller_key_canon)
            .unwrap();

        let device_key = crypto.generate_secret_key().unwrap();
        let mut device_csr_buf = [0; 256];
        let device_csr = device_key.csr(&mut device_csr_buf).unwrap();
        let mut device_key_canon = CanonPkcSecretKey::new();
        device_key.write_canon(&mut device_key_canon).unwrap();

        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let controller_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

        let controller_noc = noc_gen
            .generate(
                &crypto,
                controller_csr,
                CONTROLLER_NODE_ID,
                &[],
                VALID_FOREVER,
            )
            .unwrap();
        let fab_idx = controller_matter.with_state(|state| {
            state
                .fabrics
                .add(
                    &crypto,
                    controller_key_canon.reference(),
                    rcac,
                    controller_noc,
                    &[],
                    Some(ipk_ref),
                    0xFFF1,
                    CONTROLLER_NODE_ID,
                )
                .unwrap()
                .fab_idx()
        });
        let device_noc = noc_gen
            .generate(&crypto, device_csr, DEVICE_NODE_ID, &[], VALID_FOREVER)
            .unwrap();
        device_matter.with_state(|state| {
            state
                .fabrics
                .add(
                    &crypto,
                    device_key_canon.reference(),
                    rcac,
                    device_noc,
                    &[],
                    Some(ipk_ref),
                    0xFFF1,
                    DEVICE_NODE_ID,
                )
                .unwrap();
        });

        let (device_socket, controller_socket) = create_localhost_socket_pair();
        let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());
        let case_peer_addr = Address::Udp(controller_socket.get_ref().local_addr().unwrap());
        let (case_peer_tx, case_peer_rx) = async_channel::bounded(1);
        let responder = Responder::new(
            "case-identity",
            CaseIdentityHandler {
                crypto: &crypto,
                peers: case_peer_tx,
            },
            &device_matter,
            0,
        );
        let device_fut = async {
            futures_lite::future::race(
                device_matter.run(&crypto, &device_socket, &device_socket, NoNetwork),
                responder.run::<4>(),
            )
            .await
        };

        let controller_fut = run_with_transport(
            controller_matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork),
            async {
                let handle = CaseInitiator::connect(
                    &controller_matter,
                    &crypto,
                    fab_idx,
                    ExpectedPeerIdentity::new(FABRIC_ID, DEVICE_NODE_ID),
                    peer_addr,
                    &AcceptExpectedPeer,
                )
                .await?;
                assert_eq!(handle.peer_identity().fabric_id(), FABRIC_ID);
                assert_eq!(handle.peer_identity().node_id(), DEVICE_NODE_ID);
                assert!(controller_matter
                    .has_operational_case_session_for_peer(fab_idx, DEVICE_NODE_ID));
                let exchange = handle.open_exchange()?;
                drop(exchange);
                drop(handle);
                assert!(!controller_matter
                    .has_operational_case_session_for_peer(fab_idx, DEVICE_NODE_ID));
                let case_peer = case_peer_rx.recv().await.unwrap();
                assert_eq!(case_peer.fabric_index, fab_idx);
                assert_eq!(case_peer.node_id, CONTROLLER_NODE_ID);
                assert_eq!(case_peer.address, case_peer_addr);
                Ok(())
            },
        );

        run_device_controller(device_fut, controller_fut)
            .await
            .unwrap();
    });
}
