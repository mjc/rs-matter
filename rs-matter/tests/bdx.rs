/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! End-to-end tests of the BDX engine over a real CASE-secured exchange, each
//! transferring a multi-block image and asserting it arrives byte-for-byte:
//!
//! - the `serve`/`download` sink/source engine, and
//! - the streaming `BdxReader`/`BdxWriter` (`download`/`upload` + `accept`).

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::Poll;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::bdx::{
    self, Bdx, BdxDownloadInitiator, BdxDownloadResponder, BdxHandler, BdxReader, BdxResponder,
    BdxUploadInitiator, BdxUploadResponder, BdxWriter, ChainedBdxHandler, EmptyBdxHandler,
    TransferExtent,
};
use rs_matter::dm::clusters::ota_prov::{BdxBuffer, OtaBdxHandler, OtaImages};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::respond::ExchangeHandler;
use rs_matter::sc::{GeneralCode, OpCode as ScOpCode, StatusReport};
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::utils::storage::ReadBuf;

use crate::common::e2e::{new_default_runner, E2eLateBdxQueryRace};
use crate::common::init_env_logger;

const FILE_DESIGNATOR: &[u8] = b"firmware.ota";

// ---- Streaming API (`BdxReader` / `BdxWriter`) ----

/// Fail (rather than hang) if a streaming operation doesn't make progress.
async fn with_timeout<F, T>(fut: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    match select(
        core::pin::pin!(fut),
        core::pin::pin!(Timer::after(Duration::from_secs(30))),
    )
    .await
    {
        Either::First(r) => r,
        Either::Second(()) => panic!("BDX streaming operation timed out"),
    }
}

/// Read a whole transfer via `BdxReader`, using a deliberately non-block-aligned
/// buffer to exercise partial-block and cross-block reads.
async fn read_all(reader: &mut BdxReader<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 300];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Write a whole buffer via `BdxWriter`, in non-block-aligned chunks (and
/// honoring the partial-accept return of `write`).
async fn write_all(writer: &mut BdxWriter<'_, '_>, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        let n = writer.write(data).await?;
        assert!(n > 0);
        data = &data[n..];
    }
    Ok(())
}

/// Transfer sizes that bracket the streaming block size (1024 B): empty,
/// sub-block, exactly one/two blocks, and the off-by-one neighbours, where the
/// block-buffering and final-`BlockEof` logic is most likely to break.
const STREAM_SIZES: &[usize] = &[0, 1, 1023, 1024, 1025, 2048, 5000];

fn image_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Responder for the download test: serves the next image (one per accepted
/// exchange) via [`BdxDownloadResponder`], advertising a definite length.
struct DownloadResponder<'a> {
    images: &'a [Vec<u8>],
    next: AtomicUsize,
}

impl ExchangeHandler for DownloadResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let image = &self.images[self.next.fetch_add(1, Ordering::Relaxed)];
        let responder = BdxDownloadResponder::accept(exchange).await?;
        assert_eq!(responder.fd(), FILE_DESIGNATOR);
        let mut wbuf = [0u8; 1024];
        let mut writer = responder
            .reply(&mut wbuf, TransferExtent::Definite(image.len() as u64))
            .await?;
        write_all(&mut writer, image).await?;
        writer.finish().await
    }
}

/// `download`: the initiator drives as the Receiver (`BdxReader`), the responder
/// follows as the Sender (`BdxDownloadResponder` -> `BdxWriter`). Exercises a driving
/// reader and a following writer, across [`STREAM_SIZES`] back-to-back on one
/// session.
#[test]
fn test_bdx_download_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();
    let responder = DownloadResponder {
        images: &images,
        next: AtomicUsize::new(0),
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            for image in &images {
                let exchange = runner.initiate_exchange().await?;
                let mut reader = exchange.download(FILE_DESIGNATOR, None).await?;
                let received = with_timeout(read_all(&mut reader)).await?;
                assert_eq!(&received, image, "download size {}", image.len());
            }
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

struct WriteDownloadResponder {
    image: Vec<u8>,
}

impl ExchangeHandler for WriteDownloadResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(self.image.len() as u64))
            .await?;
        write_all(&mut writer, &self.image).await?;
        let final_len = self.image.len().min(writer.max_block_size());
        writer.finish_with_len(final_len).await?;
        assert!(writer.write(b"late").await.is_err());
        assert!(writer.commit(0).await.is_err());
        Ok(())
    }
}

struct FlushDownloadResponder {
    image: Vec<u8>,
}

struct CommitDownloadResponder {
    image: Vec<u8>,
}

impl ExchangeHandler for CommitDownloadResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(self.image.len() as u64))
            .await?;
        writer.block_buf()?[..self.image.len()].copy_from_slice(&self.image);
        writer.commit(self.image.len()).await?;
        writer.finish().await
    }
}

struct RecoverExtentDownloadResponder {
    image: Vec<u8>,
}

impl ExchangeHandler for RecoverExtentDownloadResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(self.image.len() as u64))
            .await?;
        write_all(&mut writer, &self.image[..3]).await?;
        assert!(
            writer.finish().await.is_err(),
            "undershoot must not send EOF"
        );
        write_all(&mut writer, &self.image[3..]).await?;
        assert!(
            writer.write(b"x").await.is_err(),
            "overshoot must be rejected"
        );
        writer.finish().await
    }
}

struct MixedWriteCommitDownloadResponder;

impl ExchangeHandler for MixedWriteCommitDownloadResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(4))
            .await?;
        assert_eq!(writer.write(b"ab").await?, 2);
        assert!(writer.block_buf().is_err());
        assert!(writer.commit(2).await.is_err());
        assert_eq!(writer.write(b"cd").await?, 2);
        writer.finish().await
    }
}

impl ExchangeHandler for FlushDownloadResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(self.image.len() as u64))
            .await?;
        write_all(&mut writer, &self.image).await?;
        embedded_io_async::Write::flush(&mut writer).await?;
        writer.finish().await
    }
}

async fn receive_writer_frames(mut exchange: Exchange<'_>, image: &[u8]) -> Result<(), Error> {
    let init = bdx::TransferInit {
        transfer_control: bdx::TransferControl {
            version: bdx::BDX_VERSION,
            sender_drive: true,
            receiver_drive: false,
            async_mode: false,
        },
        range_control: bdx::RangeControl::default(),
        max_block_size: 256,
        start_offset: 0,
        length: 0,
        file_designator: FILE_DESIGNATOR,
        metadata: &[],
    };
    exchange
        .send_with(|_, wb| {
            init.write(wb)?;
            Ok(Some(bdx::OpCode::ReceiveInit.into()))
        })
        .await?;

    exchange.recv_fetch().await?;
    let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
    assert_eq!(accept.length, image.len() as u64);
    let block_size = usize::from(accept.max_block_size);
    exchange.rx_done()?;

    let expected_frames = image.len().div_ceil(block_size).max(1);
    let final_len = if image.is_empty() {
        0
    } else {
        let tail = image.len() % block_size;
        if tail == 0 {
            block_size
        } else {
            tail
        }
    };
    let mut received = Vec::new();

    for index in 0..expected_frames {
        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();
        let block = bdx::Block::parse(exchange.rx()?.payload())?;
        let last = index + 1 == expected_frames;
        assert_eq!(
            meta.proto_opcode == bdx::OpCode::BlockEof as u8,
            last,
            "unexpected EOF position for {} byte write",
            image.len()
        );
        assert_eq!(block.data.len(), if last { final_len } else { block_size });
        received.extend_from_slice(block.data);
        let counter = block.block_counter;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::BlockQuery {
                    block_counter: counter,
                }
                .write(wb)?;
                Ok(Some(if last {
                    bdx::OpCode::BlockAckEof.into()
                } else {
                    bdx::OpCode::BlockAck.into()
                }))
            })
            .await?;
    }

    exchange.acknowledge().await?;
    assert_eq!(received, image);
    Ok(())
}

#[test]
fn test_bdx_writer_finishes_full_blocks_with_data_eof() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let runner = new_default_runner();
        let image = image_of(256);
        select(
            runner.run_responder(WriteDownloadResponder {
                image: image.clone(),
            }),
            async {
                receive_writer_frames(runner.initiate_exchange().await?, &image).await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });

    futures_lite::future::block_on(async {
        let runner = new_default_runner();
        let image = image_of(512);
        select(
            runner.run_responder(WriteDownloadResponder {
                image: image.clone(),
            }),
            async {
                receive_writer_frames(runner.initiate_exchange().await?, &image).await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_bdx_writer_flush_uses_declared_extent_for_final_eof() {
    init_env_logger();

    for len in [0, 1, 255, 256, 257, 512, 529] {
        futures_lite::future::block_on(async {
            let runner = new_default_runner();
            let image = image_of(len);
            select(
                runner.run_responder(FlushDownloadResponder {
                    image: image.clone(),
                }),
                async {
                    receive_writer_frames(runner.initiate_exchange().await?, &image).await?;
                    Ok::<_, Error>(())
                },
            )
            .coalesce()
            .await
            .unwrap();
        });
    }
}

#[test]
fn test_bdx_writer_commit_uses_declared_extent_for_final_eof() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let runner = new_default_runner();
        let image = image_of(17);
        select(
            runner.run_responder(CommitDownloadResponder {
                image: image.clone(),
            }),
            async {
                receive_writer_frames(runner.initiate_exchange().await?, &image).await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_bdx_writer_extent_rejection_preserves_staged_data() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let runner = new_default_runner();
        let image = image_of(5);
        select(
            runner.run_responder(RecoverExtentDownloadResponder {
                image: image.clone(),
            }),
            async {
                receive_writer_frames(runner.initiate_exchange().await?, &image).await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_bdx_writer_rejects_mixing_write_and_commit_without_data_loss() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let runner = new_default_runner();
        let image = b"abcd";
        select(
            runner.run_responder(MixedWriteCommitDownloadResponder),
            async {
                receive_writer_frames(runner.initiate_exchange().await?, image).await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_bdx_writer_indefinite_flush_and_commit_boundaries() {
    init_env_logger();

    let runner = new_default_runner();
    let images = vec![image_of(300), image_of(300)];
    let responder = UploadResponder {
        images: &images,
        next: AtomicUsize::new(0),
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            let first_image = &images[0];
            let exchange = runner.initiate_exchange().await?;
            let mut tx_buf = [0u8; 128];
            let mut writer = exchange
                .upload(
                    &mut tx_buf,
                    FILE_DESIGNATOR,
                    None,
                    TransferExtent::Indefinite,
                )
                .await?;
            embedded_io_async::Write::flush(&mut writer).await?;
            write_all(&mut writer, &first_image[..11]).await?;
            assert!(embedded_io_async::Write::flush(&mut writer).await.is_err());
            write_all(&mut writer, &first_image[11..]).await?;
            writer.finish().await?;

            let second_image = &images[1];
            let exchange = runner.initiate_exchange().await?;
            let mut tx_buf = [0u8; 128];
            let mut writer = exchange
                .upload(
                    &mut tx_buf,
                    FILE_DESIGNATOR,
                    None,
                    TransferExtent::Indefinite,
                )
                .await?;
            writer.block_buf()?[..7].copy_from_slice(b"staged!");
            assert!(writer.commit(7).await.is_err());
            write_all(&mut writer, second_image).await?;
            writer.finish().await?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

struct CancelFinalEofResponder;

impl ExchangeHandler for CancelFinalEofResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(1))
            .await?;
        writer.write(b"x").await?;

        let outcome = {
            let finish = core::pin::pin!(writer.finish_with_len(1));
            let delay = core::pin::pin!(Timer::after(Duration::from_secs(1)));
            select(finish, delay).await
        };
        assert!(matches!(outcome, Either::Second(())));

        writer.cancel().await?;
        assert!(writer.write(b"late").await.is_err());
        assert!(writer.commit(0).await.is_err());
        Ok(())
    }
}

#[test]
fn test_bdx_writer_cancel_final_eof_is_terminal() {
    init_env_logger();
    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(CancelFinalEofResponder), async {
            let mut exchange = runner.initiate_exchange().await?;
            let init = bdx::TransferInit {
                transfer_control: bdx::TransferControl {
                    version: bdx::BDX_VERSION,
                    sender_drive: true,
                    receiver_drive: false,
                    async_mode: false,
                },
                range_control: bdx::RangeControl {
                    def_len: true,
                    start_offset: false,
                    wide_range: false,
                },
                max_block_size: 256,
                start_offset: 0,
                length: 1,
                file_designator: FILE_DESIGNATOR,
                metadata: &[],
            };
            exchange
                .send_with(|_, wb| {
                    init.write(wb)?;
                    Ok(Some(bdx::OpCode::ReceiveInit.into()))
                })
                .await?;

            exchange.recv_fetch().await?;
            assert_eq!(
                exchange.rx()?.meta().proto_opcode,
                bdx::OpCode::ReceiveAccept as u8
            );
            exchange.rx_done()?;

            exchange.recv_fetch().await?;
            assert_eq!(
                exchange.rx()?.meta().proto_opcode,
                bdx::OpCode::BlockEof as u8
            );
            let block = bdx::Block::parse(exchange.rx()?.payload())?;
            assert_eq!(block.data, b"x");
            exchange.rx_done()?;
            // Intentionally omit BlockAckEof so the sender's borrowed finish
            // future is cancelled while awaiting its application acknowledgement.

            let outcome = select(
                core::pin::pin!(exchange.recv_fetch()),
                core::pin::pin!(Timer::after(Duration::from_secs(2))),
            )
            .await;
            match outcome {
                Either::First(result) => {
                    result?;
                }
                Either::Second(()) => {
                    panic!("dropping the final acknowledgement wait must send a failure report")
                }
            }
            assert_eq!(
                exchange.rx()?.meta().proto_id,
                rs_matter::sc::PROTO_ID_SECURE_CHANNEL
            );
            {
                let mut rb = ReadBuf::new(exchange.rx()?.payload());
                let status = StatusReport::read(&mut rb)?;
                assert_eq!(status.general_code, GeneralCode::Failure);
                assert_eq!(status.proto_id, bdx::PROTO_ID_BDX as u32);
                assert_eq!(
                    status.proto_code,
                    bdx::BdxStatus::TransferFailedUnknownError as u16
                );
            }
            exchange.rx_done()?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

struct CancelNegotiationResponder;

impl ExchangeHandler for CancelNegotiationResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder.prepare_reply(&mut buf).await?;
        let outcome = {
            let accept = core::pin::pin!(writer.accept(TransferExtent::Definite(1)));
            let delay = core::pin::pin!(Timer::after(Duration::from_millis(250)));
            select(accept, delay).await
        };
        assert!(matches!(outcome, Either::Second(())));

        // The first acceptance attempt is terminal once dropped; retrying must
        // not send a second ReceiveAccept.
        assert!(writer.accept(TransferExtent::Definite(1)).await.is_err());
        writer.cancel().await?;
        assert!(writer.write(b"late").await.is_err());
        assert!(writer.commit(0).await.is_err());
        Ok(())
    }
}

struct RequestedExtentResponder;

impl ExchangeHandler for RequestedExtentResponder {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0; 256];
        let mut writer = responder.prepare_reply(&mut buf).await?;
        assert!(writer.accept(TransferExtent::Definite(65)).await.is_err());
        assert!(writer.accept(TransferExtent::Indefinite).await.is_err());
        writer.accept(TransferExtent::Definite(64)).await?;
        writer.block_buf()?[..64].fill(0x5A);
        writer.finish_with_len(64).await
    }
}

#[test]
fn test_bdx_download_accept_cannot_exceed_requested_extent() {
    init_env_logger();
    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(RequestedExtentResponder), async {
            let mut exchange = runner.initiate_exchange().await?;
            let init = bdx::TransferInit {
                transfer_control: bdx::TransferControl {
                    version: bdx::BDX_VERSION,
                    sender_drive: true,
                    receiver_drive: false,
                    async_mode: false,
                },
                range_control: bdx::RangeControl {
                    def_len: true,
                    start_offset: false,
                    wide_range: false,
                },
                max_block_size: 64,
                start_offset: 0,
                length: 64,
                file_designator: FILE_DESIGNATOR,
                metadata: &[],
            };
            exchange
                .send_with(|_, wb| {
                    init.write(wb)?;
                    Ok(Some(bdx::OpCode::ReceiveInit.into()))
                })
                .await?;

            exchange.recv_fetch().await?;
            let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
            assert_eq!(accept.length, 64);
            exchange.rx_done()?;
            exchange.recv_fetch().await?;
            assert_eq!(
                exchange.rx()?.meta().proto_opcode,
                bdx::OpCode::BlockEof as u8
            );
            let block = bdx::Block::parse(exchange.rx()?.payload())?;
            assert_eq!(block.block_counter, 0);
            assert_eq!(block.data, &[0x5A; 64]);
            exchange.rx_done()?;
            exchange
                .send_with(|_, wb| {
                    bdx::BlockQuery { block_counter: 0 }.write(wb)?;
                    Ok(Some(bdx::OpCode::BlockAckEof.into()))
                })
                .await?;
            exchange.acknowledge().await?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_bdx_writer_cancel_negotiation_is_terminal() {
    init_env_logger();
    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(CancelNegotiationResponder), async {
            let mut exchange = runner.initiate_exchange().await?;
            let init = bdx::TransferInit {
                transfer_control: bdx::TransferControl {
                    version: bdx::BDX_VERSION,
                    sender_drive: true,
                    receiver_drive: false,
                    async_mode: false,
                },
                range_control: bdx::RangeControl::default(),
                max_block_size: 256,
                start_offset: 0,
                length: 0,
                file_designator: FILE_DESIGNATOR,
                metadata: &[],
            };
            exchange
                .send_with(|_, wb| {
                    init.write(wb)?;
                    Ok(Some(bdx::OpCode::ReceiveInit.into()))
                })
                .await?;

            exchange.recv_fetch().await?;
            assert_eq!(
                exchange.rx()?.meta().proto_opcode,
                bdx::OpCode::ReceiveAccept as u8
            );
            // Keep the received message held until the sender has cancelled its
            // pending `accept` future and is waiting to drain this MRP ack.
            Timer::after(Duration::from_millis(500)).await;
            exchange.rx_done()?;
            exchange.acknowledge().await?;

            let outcome = select(
                core::pin::pin!(exchange.recv_fetch()),
                core::pin::pin!(Timer::after(Duration::from_secs(2))),
            )
            .await;
            match outcome {
                Either::First(result) => {
                    result?;
                }
                Either::Second(()) => {
                    panic!("cancelled negotiation must report failure to the peer")
                }
            }
            assert_eq!(
                exchange.rx()?.meta().proto_id,
                rs_matter::sc::PROTO_ID_SECURE_CHANNEL
            );
            {
                let mut rb = ReadBuf::new(exchange.rx()?.payload());
                let status = StatusReport::read(&mut rb)?;
                assert_eq!(status.general_code, GeneralCode::Failure);
                assert_eq!(status.proto_id, bdx::PROTO_ID_BDX as u32);
                assert_eq!(
                    status.proto_code,
                    bdx::BdxStatus::TransferFailedUnknownError as u16
                );
            }
            exchange.rx_done()?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Responder that honors a requested start offset: serves `image[start_offset..]`,
/// advertising only the remaining bytes.
struct OffsetDownloadResponder<'a> {
    image: &'a [u8],
}

impl ExchangeHandler for OffsetDownloadResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let tail = &self.image[responder.start_offset() as usize..];
        let mut wbuf = [0u8; 1024];
        let mut writer = responder
            .reply(&mut wbuf, TransferExtent::Definite(tail.len() as u64))
            .await?;
        write_all(&mut writer, tail).await?;
        writer.finish().await
    }
}

/// `download` with a non-zero start offset: the initiator asks to resume from a
/// byte offset, the responder serves the tail and advertises the remaining length.
#[test]
fn test_bdx_download_with_offset() {
    init_env_logger();

    let runner = new_default_runner();
    let image = image_of(5000);
    let offset = 1234u64;
    let responder = OffsetDownloadResponder { image: &image };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.download(FILE_DESIGNATOR, Some(offset)).await?;
            // The advertised length is the remaining bytes from the offset.
            assert_eq!(reader.len(), Some(image.len() as u64 - offset));
            let received = with_timeout(read_all(&mut reader)).await?;
            assert_eq!(&received, &image[offset as usize..]);
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

struct TestOtaImage(Vec<u8>);

impl OtaImages for TestOtaImage {
    async fn size(&self, fd: &[u8]) -> Option<u64> {
        (fd == FILE_DESIGNATOR).then_some(self.0.len() as u64)
    }

    async fn read(&self, fd: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if fd != FILE_DESIGNATOR {
            return Err(ErrorCode::Invalid.into());
        }
        let offset = usize::try_from(offset).map_err(|_| ErrorCode::Invalid)?;
        let Some(bytes) = self.0.get(offset..) else {
            return Ok(0);
        };
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
}

struct ShortOtaImage {
    bytes: Vec<u8>,
    declared_len: u64,
}

impl OtaImages for ShortOtaImage {
    async fn size(&self, fd: &[u8]) -> Option<u64> {
        (fd == FILE_DESIGNATOR).then_some(self.declared_len)
    }

    async fn read(&self, fd: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if fd != FILE_DESIGNATOR {
            return Err(ErrorCode::Invalid.into());
        }
        let offset = usize::try_from(offset).map_err(|_| ErrorCode::Invalid)?;
        let Some(bytes) = self.bytes.get(offset..) else {
            return Ok(0);
        };
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
}

/// Send a definite-length ReceiveInit directly because the public convenience
/// download API currently proposes an indefinite transfer.
async fn ota_download_window(
    mut exchange: Exchange<'_>,
    image: &[u8],
    offset: u64,
    requested: u64,
    expected_len: Option<u64>,
) -> Result<(), Error> {
    let init = bdx::TransferInit {
        transfer_control: bdx::TransferControl {
            version: bdx::BDX_VERSION,
            sender_drive: true,
            receiver_drive: false,
            async_mode: false,
        },
        range_control: bdx::RangeControl {
            def_len: true,
            start_offset: offset != 0,
            wide_range: offset > u32::MAX as u64 || requested > u32::MAX as u64,
        },
        max_block_size: 256,
        start_offset: offset,
        length: requested,
        file_designator: FILE_DESIGNATOR,
        metadata: &[],
    };
    exchange
        .send_with(|_, wb| {
            init.write(wb)?;
            Ok(Some(bdx::OpCode::ReceiveInit.into()))
        })
        .await?;

    exchange.recv_fetch().await?;
    if expected_len.is_none() {
        assert_eq!(
            exchange.rx()?.meta().proto_id,
            rs_matter::sc::PROTO_ID_SECURE_CHANNEL
        );
        {
            let mut rb = ReadBuf::new(exchange.rx()?.payload());
            let status = StatusReport::read(&mut rb)?;
            assert_eq!(status.general_code, GeneralCode::Failure);
            assert_eq!(status.proto_id, bdx::PROTO_ID_BDX as u32);
            assert_eq!(
                status.proto_code,
                bdx::BdxStatus::StartOffsetNotSupported as u16
            );
        }
        exchange.rx_done()?;
        return Ok(());
    }
    assert_eq!(
        exchange.rx()?.meta().proto_opcode,
        bdx::OpCode::ReceiveAccept as u8
    );
    let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
    assert!(accept.range_control.def_len);
    let expected_len = expected_len.unwrap();
    assert_eq!(accept.length, expected_len);
    let block_size = usize::from(accept.max_block_size);
    let expected_len_usize = usize::try_from(expected_len).unwrap();
    let expected_frames = (expected_len_usize + block_size - 1)
        .checked_div(block_size)
        .unwrap()
        .max(1);
    let expected_final_len = if expected_len_usize == 0 {
        0
    } else {
        let remainder = expected_len_usize % block_size;
        if remainder == 0 {
            block_size
        } else {
            remainder
        }
    };
    exchange.rx_done()?;

    let mut received = Vec::new();
    let mut expected_counter = 0;
    let mut frame_index = 0;
    loop {
        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();
        let block = bdx::Block::parse(exchange.rx()?.payload())?;
        assert_eq!(block.block_counter, expected_counter);
        received.extend_from_slice(block.data);
        let eof = meta.proto_opcode == bdx::OpCode::BlockEof as u8;
        assert!(eof || meta.proto_opcode == bdx::OpCode::Block as u8);
        let is_final = frame_index + 1 == expected_frames;
        assert_eq!(eof, is_final, "unexpected BDX EOF position");
        let expected_block_len = if is_final {
            expected_final_len
        } else {
            block_size
        };
        assert_eq!(
            block.data.len(),
            expected_block_len,
            "unexpected data length in BDX frame {frame_index}"
        );
        let counter = block.block_counter;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::BlockQuery {
                    block_counter: counter,
                }
                .write(wb)?;
                Ok(Some(if eof {
                    bdx::OpCode::BlockAckEof.into()
                } else {
                    bdx::OpCode::BlockAck.into()
                }))
            })
            .await?;
        if eof {
            break;
        }
        expected_counter = expected_counter.wrapping_add(1);
        frame_index += 1;
    }
    exchange.acknowledge().await?;
    let end = usize::try_from(offset).unwrap() + usize::try_from(expected_len).unwrap();
    assert_eq!(received, image[offset as usize..end]);
    Ok(())
}

#[test]
fn test_ota_bdx_definite_length_windows() {
    init_env_logger();
    let runner = new_default_runner();
    let image = image_of(5000);
    let buffers = PooledBuffers::<BdxBuffer, 1>::new();
    let handler = Bdx::new(OtaBdxHandler::new(&buffers, TestOtaImage(image.clone())));

    futures_lite::future::block_on(async {
        select(runner.run_responder(handler), async {
            ota_download_window(
                runner.initiate_exchange().await?,
                &image,
                123,
                321,
                Some(321),
            )
            .await?;
            for window_len in [1, 255, 256, 257, 512] {
                ota_download_window(
                    runner.initiate_exchange().await?,
                    &image,
                    100,
                    window_len,
                    Some(window_len),
                )
                .await?;
            }
            ota_download_window(
                runner.initiate_exchange().await?,
                &image,
                4900,
                500,
                Some(100),
            )
            .await?;
            // A zero DEFLEN means indefinite per Matter Core, so the provider
            // serves the remaining image. An offset exactly at EOF has a true
            // zero-byte window even with a positive requested length.
            ota_download_window(
                runner.initiate_exchange().await?,
                &image,
                200,
                0,
                Some(4800),
            )
            .await?;
            ota_download_window(
                runner.initiate_exchange().await?,
                &image,
                5000,
                100,
                Some(0),
            )
            .await?;
            ota_download_window(
                runner.initiate_exchange().await?,
                &image,
                123,
                u64::MAX,
                Some(4877),
            )
            .await?;
            ota_download_window(runner.initiate_exchange().await?, &image, 5001, 100, None).await?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

#[test]
fn test_ota_bdx_short_image_source_aborts_definite_transfer() {
    init_env_logger();
    let runner = new_default_runner();
    let buffers = PooledBuffers::<BdxBuffer, 1>::new();
    let handler = Bdx::new(OtaBdxHandler::new(
        &buffers,
        ShortOtaImage {
            bytes: image_of(100),
            declared_len: 300,
        },
    ));

    futures_lite::future::block_on(async {
        select(runner.run_responder(handler), async {
            let mut exchange = runner.initiate_exchange().await?;
            let init = bdx::TransferInit {
                transfer_control: bdx::TransferControl {
                    version: bdx::BDX_VERSION,
                    sender_drive: true,
                    receiver_drive: false,
                    async_mode: false,
                },
                range_control: bdx::RangeControl {
                    def_len: true,
                    start_offset: false,
                    wide_range: false,
                },
                max_block_size: 256,
                start_offset: 0,
                length: 300,
                file_designator: FILE_DESIGNATOR,
                metadata: &[],
            };
            exchange
                .send_with(|_, wb| {
                    init.write(wb)?;
                    Ok(Some(bdx::OpCode::ReceiveInit.into()))
                })
                .await?;

            with_timeout(async { exchange.recv_fetch().await.map(|_| ()) }).await?;
            let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
            assert_eq!(accept.length, 300);
            exchange.rx_done()?;

            let mut received_len = 0usize;
            let mut expected_counter = 0;
            loop {
                with_timeout(async { exchange.recv_fetch().await.map(|_| ()) }).await?;
                let meta = exchange.rx()?.meta();
                if meta.proto_id == rs_matter::sc::PROTO_ID_SECURE_CHANNEL {
                    {
                        let mut rb = ReadBuf::new(exchange.rx()?.payload());
                        let status = StatusReport::read(&mut rb)?;
                        assert_eq!(status.general_code, GeneralCode::Failure);
                        assert_eq!(status.proto_id, bdx::PROTO_ID_BDX as u32);
                        assert_eq!(
                            status.proto_code,
                            bdx::BdxStatus::TransferFailedUnknownError as u16
                        );
                    }
                    assert!(received_len < 300);
                    exchange.rx_done()?;
                    break;
                }

                assert_eq!(meta.proto_opcode, bdx::OpCode::Block as u8);
                let block = bdx::Block::parse(exchange.rx()?.payload())?;
                assert_eq!(block.block_counter, expected_counter);
                received_len += block.data.len();
                let counter = block.block_counter;
                exchange.rx_done()?;
                exchange
                    .send_with(|_, wb| {
                        bdx::BlockQuery {
                            block_counter: counter,
                        }
                        .write(wb)?;
                        Ok(Some(bdx::OpCode::BlockAck.into()))
                    })
                    .await?;
                expected_counter = expected_counter.wrapping_add(1);
            }

            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Responder that asserts the upload's declared start offset and reads the tail.
struct OffsetUploadResponder<'a> {
    image: &'a [u8],
    offset: u64,
}

impl ExchangeHandler for OffsetUploadResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxUploadResponder::accept(exchange).await?;
        assert_eq!(responder.start_offset(), self.offset);
        let mut reader = responder.reply().await?;
        let received = read_all(&mut reader).await?;
        assert_eq!(&received, &self.image[self.offset as usize..]);
        Ok(())
    }
}

/// `upload` with a non-zero start offset: the initiator declares it is resuming
/// from a byte offset and streams the tail; the responder sees the offset.
#[test]
fn test_bdx_upload_with_offset() {
    init_env_logger();

    let runner = new_default_runner();
    let image = image_of(5000);
    let offset = 1234u64;
    let responder = OffsetUploadResponder {
        image: &image,
        offset,
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            let exchange = runner.initiate_exchange().await?;
            let mut wbuf = [0u8; 1024];
            let mut writer = exchange
                .upload(
                    &mut wbuf,
                    FILE_DESIGNATOR,
                    Some(offset),
                    TransferExtent::Definite((image.len() as u64) - offset),
                )
                .await?;
            write_all(&mut writer, &image[offset as usize..]).await?;
            writer.finish().await?;
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Responder for the upload test: reads the next image (one per accepted exchange)
/// via [`BdxUploadResponder`] and asserts it.
struct UploadResponder<'a> {
    images: &'a [Vec<u8>],
    next: AtomicUsize,
}

impl ExchangeHandler for UploadResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let image = &self.images[self.next.fetch_add(1, Ordering::Relaxed)];
        let responder = BdxUploadResponder::accept(exchange).await?;
        assert_eq!(responder.fd(), FILE_DESIGNATOR);
        let mut reader = responder.reply().await?;
        let received = read_all(&mut reader).await?;
        assert_eq!(&received, image, "upload size {}", image.len());
        Ok(())
    }
}

/// `upload`: the initiator drives as the Sender (`BdxWriter`), the responder
/// follows as the Receiver (`BdxUploadResponder` -> `BdxReader`). Exercises a
/// driving writer and a following reader, across [`STREAM_SIZES`] back-to-back on
/// one session.
#[test]
fn test_bdx_upload_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();
    let responder = UploadResponder {
        images: &images,
        next: AtomicUsize::new(0),
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            for (index, image) in images.iter().enumerate() {
                let exchange = runner.initiate_exchange().await?;
                let mut wbuf = [0u8; 1024];
                let mut writer = exchange
                    .upload(
                        &mut wbuf,
                        FILE_DESIGNATOR,
                        None,
                        if index % 2 == 0 {
                            TransferExtent::Indefinite
                        } else {
                            TransferExtent::Definite(image.len() as u64)
                        },
                    )
                    .await?;
                with_timeout(async {
                    write_all(&mut writer, image).await?;
                    writer.finish().await
                })
                .await?;
            }
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

// ---- Handler routing (`Bdx` / `BdxHandler`) ----

const SERVE_FD: &[u8] = b"download.img";
const PROCESS_FD: &[u8] = b"upload.log";

/// A [`BdxHandler`] that *serves* (sends) a single image on [`SERVE_FD`].
struct ImageServer {
    image: Vec<u8>,
}

impl BdxHandler for ImageServer {
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        matches!(responder, BdxResponder::Download(_)) && responder.fd() == SERVE_FD
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        let responder = match responder {
            BdxResponder::Download(responder) => responder,
            other => return other.reject(bdx::BdxStatus::FileDesignatorUnknown).await,
        };

        let mut wbuf = [0u8; 512];
        let mut writer = responder
            .reply(&mut wbuf, TransferExtent::Definite(self.image.len() as u64))
            .await?;
        write_all(&mut writer, &self.image).await?;
        writer.finish().await
    }
}

/// A [`BdxHandler`] that *processes* (receives) a single upload on [`PROCESS_FD`],
/// asserting the bytes it receives.
struct LogSink {
    expected: Vec<u8>,
}

impl BdxHandler for LogSink {
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        matches!(responder, BdxResponder::Upload(_)) && responder.fd() == PROCESS_FD
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        let responder = match responder {
            BdxResponder::Upload(responder) => responder,
            other => return other.reject(bdx::BdxStatus::FileDesignatorUnknown).await,
        };

        let mut reader = responder.reply().await?;
        let received = read_all(&mut reader).await?;
        assert_eq!(received, self.expected, "processed upload mismatch");

        Ok(())
    }
}

/// A single [`Bdx`] handler fronts two services on `PROTO_ID_BDX`, dispatched by
/// file designator and direction: a download routes to the (sending) image
/// server, an upload to the (receiving) log sink, and an unknown designator is
/// rejected by the chain terminator.
#[test]
fn test_bdx_server_routing() {
    init_env_logger();

    let runner = new_default_runner();

    let download = image_of(2500);
    let upload = image_of(1500);

    let handler = ChainedBdxHandler::new(
        ImageServer {
            image: download.clone(),
        },
        ChainedBdxHandler::new(
            LogSink {
                expected: upload.clone(),
            },
            EmptyBdxHandler,
        ),
    );
    let bdx = Bdx::new(handler);

    futures_lite::future::block_on(async {
        select(runner.run_responder(bdx), async {
            // A download routes to the image server.
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.download(SERVE_FD, None).await?;
            let received = with_timeout(read_all(&mut reader)).await?;
            assert_eq!(received, download);

            // An upload routes to the log sink (which asserts the payload).
            let exchange = runner.initiate_exchange().await?;
            let mut wbuf = [0u8; 512];
            let mut writer = exchange
                .upload(
                    &mut wbuf,
                    PROCESS_FD,
                    None,
                    TransferExtent::Definite(upload.len() as u64),
                )
                .await?;
            with_timeout(async {
                write_all(&mut writer, &upload).await?;
                writer.finish().await
            })
            .await?;

            // An unknown designator is rejected by the chain terminator.
            let exchange = runner.initiate_exchange().await?;
            let result =
                with_timeout(async { exchange.download(b"unknown.bin", None).await.map(|_| ()) })
                    .await;
            assert!(result.is_err(), "unknown file designator must be rejected");

            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

// ---- Abort / error paths (raw "misbehaving" responders) ----

/// Send a BDX failure `StatusReport` (a Secure Channel `StatusReport` whose
/// payload names the BDX protocol).
async fn send_bdx_status(exchange: &mut Exchange<'_>, status: bdx::BdxStatus) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            status.as_report().write(wb)?;
            Ok(Some(ScOpCode::StatusReport.meta()))
        })
        .await
}

/// A responder that rejects the transfer at negotiation: it consumes the opening
/// `*Init` and replies with a `StatusReport` instead of an `*Accept`.
struct RejectInitHandler;

impl ExchangeHandler for RejectInitHandler {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        send_bdx_status(&mut exchange, bdx::BdxStatus::FileDesignatorUnknown).await
    }
}

/// `download` must surface an error when the responder rejects the transfer with a
/// `StatusReport` during negotiation.
#[test]
fn test_bdx_download_rejected_at_negotiation() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(RejectInitHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let result =
                with_timeout(async { exchange.download(FILE_DESIGNATOR, None).await.map(|_| ()) })
                    .await;
            assert!(
                result.is_err(),
                "download must fail when the peer rejects it"
            );
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// A responder that accepts a download, sends one block, then aborts mid-stream with
/// a `StatusReport` instead of the next block.
struct AbortMidStreamHandler;

impl ExchangeHandler for AbortMidStreamHandler {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        // Accept the ReceiveInit as a (driving) sender.
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::TransferAccept {
                    receive: true,
                    transfer_control: bdx::TransferControl {
                        version: bdx::BDX_VERSION,
                        sender_drive: true,
                        receiver_drive: false,
                        async_mode: false,
                    },
                    range_control: bdx::RangeControl::default(),
                    max_block_size: 256,
                    length: 0,
                    metadata: &[],
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::ReceiveAccept.into()))
            })
            .await?;

        // Send the first block...
        exchange
            .send_with(|_, wb| {
                bdx::Block {
                    block_counter: 0,
                    data: b"abcd",
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::Block.into()))
            })
            .await?;

        // ...consume its BlockAck, then abort instead of sending the next block.
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        send_bdx_status(&mut exchange, bdx::BdxStatus::TransferFailedUnknownError).await
    }
}

/// `BdxReader::read` must surface an error when the sender aborts mid-stream
/// (after a valid block has already been delivered).
#[test]
fn test_bdx_read_aborted_mid_stream() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(AbortMidStreamHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.download(FILE_DESIGNATOR, None).await?;

            with_timeout(async {
                let mut buf = [0u8; 64];

                // The first block arrives intact.
                let n = reader.read(&mut buf).await?;
                assert_eq!(&buf[..n], b"abcd");

                // The next read acknowledges block 0, then hits the abort.
                assert!(
                    reader.read(&mut buf).await.is_err(),
                    "read must fail after a mid-stream abort"
                );

                Ok::<_, Error>(())
            })
            .await
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// The peer sends one block and waits for the next receiver control message.
/// Cancellation must send a BDX StatusReport instead of requesting another block.
struct WaitForCancelHandler;

impl ExchangeHandler for WaitForCancelHandler {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::TransferAccept {
                    receive: true,
                    transfer_control: bdx::TransferControl {
                        version: bdx::BDX_VERSION,
                        sender_drive: true,
                        receiver_drive: false,
                        async_mode: false,
                    },
                    range_control: bdx::RangeControl::default(),
                    max_block_size: 256,
                    length: 0,
                    metadata: &[],
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::ReceiveAccept.into()))
            })
            .await?;

        exchange
            .send_with(|_, wb| {
                bdx::Block {
                    block_counter: 0,
                    data: b"abcd",
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::Block.into()))
            })
            .await?;

        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();
        assert_eq!(meta.proto_id, rs_matter::sc::PROTO_ID_SECURE_CHANNEL);
        assert_eq!(meta.proto_opcode, ScOpCode::StatusReport as u8);
        let (proto_id, proto_code) = {
            let mut rb = ReadBuf::new(exchange.rx()?.payload());
            let status = StatusReport::read(&mut rb)?;
            (status.proto_id, status.proto_code)
        };
        assert_eq!(proto_id, bdx::PROTO_ID_BDX as u32);
        assert_eq!(
            proto_code,
            bdx::BdxStatus::TransferFailedUnknownError as u16
        );
        exchange.rx_done()?;
        Ok(())
    }
}

/// The peer accepts an upload and must observe cancellation instead of data.
struct WaitForUploadCancelHandler<'a>(&'a AtomicBool);

impl ExchangeHandler for WaitForUploadCancelHandler<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxUploadResponder::accept(exchange).await?;
        let mut reader = responder.reply().await?;
        let mut buf = [0u8; 16];
        assert!(
            reader.read(&mut buf).await.is_err(),
            "writer cancellation must arrive before any data block"
        );
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

/// Select receiver-driven upload and wait for cancellation instead of the
/// requestor's first BlockQuery.
struct PauseBeforeUploadBlockQueryHandler<'a>(&'a AtomicBool);

impl ExchangeHandler for PauseBeforeUploadBlockQueryHandler<'_> {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        assert_eq!(
            exchange.rx()?.meta().proto_opcode,
            bdx::OpCode::SendInit as u8
        );
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::TransferAccept {
                    receive: false,
                    transfer_control: bdx::TransferControl {
                        version: bdx::BDX_VERSION,
                        sender_drive: false,
                        receiver_drive: true,
                        async_mode: false,
                    },
                    range_control: bdx::RangeControl::default(),
                    max_block_size: 128,
                    length: 0,
                    metadata: &[],
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::SendAccept.into()))
            })
            .await?;

        // A BlockQuery or data block here means the dropped commit resumed the
        // transfer instead of allowing its caller to abort it.
        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();
        assert_eq!(meta.proto_id, rs_matter::sc::PROTO_ID_SECURE_CHANNEL);
        assert_eq!(meta.proto_opcode, ScOpCode::StatusReport as u8);
        let (proto_id, proto_code) = {
            let mut rb = ReadBuf::new(exchange.rx()?.payload());
            let status = StatusReport::read(&mut rb)?;
            (status.proto_id, status.proto_code)
        };
        assert_eq!(proto_id, bdx::PROTO_ID_BDX as u32);
        assert_eq!(
            proto_code,
            bdx::BdxStatus::TransferFailedUnknownError as u16
        );
        exchange.rx_done()?;
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

/// Mirrors the server download path: the responder sends one requested block,
/// then a second commit waits for the requestor's next BlockQuery. Cancellation
/// must replace that pending commit with a BDX failure report.
struct CancelDownloadAfterFirstBlockHandler<'a>(&'a AtomicUsize);

impl ExchangeHandler for CancelDownloadAfterFirstBlockHandler<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        assert_eq!(responder.fd(), FILE_DESIGNATOR);

        let mut buf = [0u8; 1024];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(2048))
            .await?;

        writer.block_buf()?[..1024].fill(0xA5);
        writer.commit(1024).await?;
        self.0.store(1, Ordering::Release);

        writer.block_buf()?[..1024].fill(0x5A);
        let pending = {
            let mut commit = core::pin::pin!(writer.commit(1024));
            core::future::poll_fn(|cx| match commit.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(true),
                Poll::Ready(_) => Poll::Ready(false),
            })
            .await
        };
        assert!(pending, "second commit must wait for BlockQuery counter 1");
        self.0.store(2, Ordering::Release);

        writer.cancel().await?;
        self.0.store(3, Ordering::Release);
        Ok(())
    }
}

/// Keep the first receiver-driven block unacknowledged until the peer requests
/// counter 1. Cancellation must drain that outstanding reliable send before it
/// can send the BDX failure report.
struct CancelDownloadWithUnackedBlockHandler<'a>(&'a AtomicUsize);

impl ExchangeHandler for CancelDownloadWithUnackedBlockHandler<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0u8; 1024];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(2048))
            .await?;
        writer.block_buf()?[..1024].fill(0xA5);

        let commit_outcome = {
            let mut commit = core::pin::pin!(writer.commit(1024));
            let commit_pending = core::future::poll_fn(|cx| match commit.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(true),
                Poll::Ready(_) => Poll::Ready(false),
            })
            .await;
            assert!(
                commit_pending,
                "commit must wait for the peer's first BlockQuery"
            );

            select(
                commit.as_mut(),
                core::future::poll_fn(|cx| {
                    if self.0.load(Ordering::Acquire) == 1 {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }),
            )
            .await
        };
        assert!(
            matches!(commit_outcome, Either::Second(())),
            "the peer must observe block 0 before the commit future is dropped"
        );
        self.0.store(2, Ordering::Release);
        let mut cancel = core::pin::pin!(writer.cancel());
        let immediate = core::future::poll_fn(|cx| match cancel.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(None),
            Poll::Ready(result) => Poll::Ready(Some(result)),
        })
        .await;

        match immediate {
            Some(Ok(())) => {
                self.0.store(3, Ordering::Release);
                Ok(())
            }
            Some(Err(error)) => {
                self.0.store(4, Ordering::Release);
                Err(error)
            }
            None => {
                cancel.await?;
                self.0.store(3, Ordering::Release);
                Ok(())
            }
        }
    }
}

/// Cancel after Block(0) is acknowledged. The fake requestor then sends a
/// reliable, same-exchange Query(1) without a piggyback ACK and queues the
/// StatusReport ACK behind it in the server's RX channel.
struct CancelDownloadWithLateBlockQueryHandler<'a>(&'a AtomicBool);

impl ExchangeHandler for CancelDownloadWithLateBlockQueryHandler<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let responder = BdxDownloadResponder::accept(exchange).await?;
        let mut buf = [0u8; 1024];
        let mut writer = responder
            .reply(&mut buf, TransferExtent::Definite(2048))
            .await?;
        writer.block_buf()?[..1024].fill(0xA5);
        writer.commit(1024).await?;

        writer.cancel().await?;
        self.0.store(true, Ordering::Release);
        assert!(
            writer.write(&[0x5A]).await.is_err(),
            "a cancelled writer must not send another block"
        );
        Ok(())
    }
}

/// Accept a receiver-driven download, send one block, then finish the handler.
/// This lets the client simulate a transport/session failure before cancellation.
struct EndAfterFirstBlockHandler;

impl ExchangeHandler for EndAfterFirstBlockHandler {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::TransferAccept {
                    receive: true,
                    transfer_control: bdx::TransferControl {
                        version: bdx::BDX_VERSION,
                        sender_drive: false,
                        receiver_drive: true,
                        async_mode: false,
                    },
                    range_control: bdx::RangeControl::default(),
                    max_block_size: 256,
                    length: 0,
                    metadata: &[],
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::ReceiveAccept.into()))
            })
            .await?;

        exchange.recv_fetch().await?;
        assert_eq!(
            exchange.rx()?.meta().proto_opcode,
            bdx::OpCode::BlockQuery as u8
        );
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::Block {
                    block_counter: 0,
                    data: b"abcd",
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::Block.into()))
            })
            .await?;
        Ok(())
    }
}

/// Cancelling a partially consumed download reports failure to the peer and
/// leaves the reader terminal, so it cannot request or receive another block.
#[test]
fn test_bdx_reader_cancel_sends_status_and_stops_transfer() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(WaitForCancelHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.download(FILE_DESIGNATOR, None).await?;

            with_timeout(async {
                let mut buf = [0u8; 2];
                assert_eq!(reader.read(&mut buf).await?, 2);
                assert_eq!(&buf, b"ab");

                reader.cancel().await?;

                let mut buf = [0u8; 8];
                assert_eq!(reader.read(&mut buf).await?, 0);
                Ok::<_, Error>(())
            })
            .await
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Even when the abort StatusReport cannot be sent, cancellation is terminal and
/// the reader must not try to send another BlockQuery.
#[test]
fn test_bdx_reader_stays_terminal_when_cancel_send_fails() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(EndAfterFirstBlockHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let session_id = runner
                .matter_client()
                .with_state(|state| state.sessions.iter().next().unwrap().id());
            let mut reader = exchange.download(FILE_DESIGNATOR, None).await?;

            with_timeout(async {
                let mut buf = [0u8; 2];
                assert_eq!(reader.read(&mut buf).await?, 2);
                assert_eq!(&buf, b"ab");

                runner
                    .matter_client()
                    .with_state(|state| assert!(state.sessions.remove(session_id).is_some()));
                assert!(reader.cancel().await.is_err());

                let mut buf = [0u8; 8];
                assert_eq!(reader.read(&mut buf).await?, 0);
                Ok::<_, Error>(())
            })
            .await
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Writer cancellation sends the failure StatusReport before any staged bytes,
/// and later writes fail locally.
#[test]
fn test_bdx_writer_cancel_sends_status_and_stops_transfer() {
    init_env_logger();

    let runner = new_default_runner();
    let report_received = AtomicBool::new(false);

    futures_lite::future::block_on(async {
        select(
            runner.run_responder(WaitForUploadCancelHandler(&report_received)),
            async {
                let exchange = runner.initiate_exchange().await?;
                let mut tx_buf = [0u8; 128];
                let mut writer = exchange
                    .upload(
                        &mut tx_buf,
                        FILE_DESIGNATOR,
                        None,
                        TransferExtent::Definite(12),
                    )
                    .await?;

                assert_eq!(writer.write(b"staged data").await?, 11);
                writer.cancel().await?;
                assert!(writer.write(b"later data").await.is_err());

                with_timeout(async {
                    core::future::poll_fn(|cx| {
                        if report_received.load(Ordering::Acquire) {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok::<_, Error>(())
                })
                .await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

/// A pending receiver-driven block commit can be dropped and cancelled. The
/// requestor has not sent its first BlockQuery, so only the abort report is valid.
#[test]
fn test_bdx_writer_cancel_after_pending_commit() {
    init_env_logger();

    let runner = new_default_runner();
    let report_received = AtomicBool::new(false);

    futures_lite::future::block_on(async {
        select(
            runner.run_responder(PauseBeforeUploadBlockQueryHandler(&report_received)),
            async {
                let exchange = runner.initiate_exchange().await?;
                let mut tx_buf = [0u8; 128];
                let mut writer = exchange
                    .upload(
                        &mut tx_buf,
                        FILE_DESIGNATOR,
                        None,
                        TransferExtent::Definite(256),
                    )
                    .await?;
                writer.block_buf()?[..10].copy_from_slice(b"block data");

                let commit_pending = {
                    let mut commit = core::pin::pin!(writer.commit(10));
                    core::future::poll_fn(|cx| match commit.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(true),
                        Poll::Ready(_) => Poll::Ready(false),
                    })
                    .await
                };
                assert!(commit_pending, "commit should wait for BlockQuery");
                assert!(writer.write(b"later").await.is_err());
                assert!(writer.commit(1).await.is_err());
                assert!(embedded_io_async::Write::flush(&mut writer).await.is_err());
                assert!(writer.block_buf().is_err());

                with_timeout(async {
                    writer.cancel().await?;
                    assert!(writer.write(b"later").await.is_err());
                    core::future::poll_fn(|cx| {
                        if report_received.load(Ordering::Acquire) {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok::<_, Error>(())
                })
                .await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

/// The production download negotiation transfers block 0, then pauses before
/// requesting block 1. A dropped second commit must be cancellable and must not
/// send block 1 after the failure report.
#[test]
fn test_bdx_download_writer_cancel_after_second_commit_pending() {
    init_env_logger();

    let runner = new_default_runner();
    let server_phase = AtomicUsize::new(0);

    futures_lite::future::block_on(async {
        select(
            runner.run_responder(CancelDownloadAfterFirstBlockHandler(&server_phase)),
            async {
                let mut exchange = runner.initiate_exchange().await?;
                exchange
                    .send_with(|_, wb| {
                        bdx::TransferInit {
                            transfer_control: bdx::TransferControl {
                                version: bdx::BDX_VERSION,
                                sender_drive: true,
                                receiver_drive: true,
                                async_mode: false,
                            },
                            range_control: bdx::RangeControl::default(),
                            max_block_size: 1024,
                            start_offset: 0,
                            length: 0,
                            file_designator: FILE_DESIGNATOR,
                            metadata: &[],
                        }
                        .write(wb)?;
                        Ok(Some(bdx::OpCode::ReceiveInit.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
                assert!(accept.transfer_control.receiver_drive);
                assert!(!accept.transfer_control.sender_drive);
                assert_eq!(accept.max_block_size, 1024);
                exchange.rx_done()?;

                exchange
                    .send_with(|_, wb| {
                        bdx::BlockQuery { block_counter: 0 }.write(wb)?;
                        Ok(Some(bdx::OpCode::BlockQuery.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                assert_eq!(exchange.rx()?.meta().proto_opcode, bdx::OpCode::Block as u8);
                let block = bdx::Block::parse(exchange.rx()?.payload())?;
                assert_eq!(block.block_counter, 0);
                assert_eq!(block.data, &[0xA5; 1024]);
                server_phase.store(1, Ordering::Release);
                exchange.rx_done()?;
                exchange.acknowledge().await?;

                exchange.recv_fetch().await?;
                let meta = exchange.rx()?.meta();
                assert_eq!(meta.proto_id, rs_matter::sc::PROTO_ID_SECURE_CHANNEL);
                assert_eq!(meta.proto_opcode, ScOpCode::StatusReport as u8);
                let (proto_id, proto_code) = {
                    let mut rb = ReadBuf::new(exchange.rx()?.payload());
                    let report = StatusReport::read(&mut rb)?;
                    (report.proto_id, report.proto_code)
                };
                assert_eq!(proto_id, bdx::PROTO_ID_BDX as u32);
                assert_eq!(
                    proto_code,
                    bdx::BdxStatus::TransferFailedUnknownError as u16
                );
                assert_eq!(server_phase.load(Ordering::Acquire), 2);
                exchange.rx_done()?;
                exchange.acknowledge().await?;

                with_timeout(async {
                    core::future::poll_fn(|cx| {
                        if server_phase.load(Ordering::Acquire) == 3 {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok::<_, Error>(())
                })
                .await?;

                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

/// A delivered block remains unacknowledged while cancellation begins. The
/// peer's next BlockQuery releases the outstanding MRP send, after which the
/// writer must report failure instead of sending block 1.
#[test]
fn test_bdx_download_cancel_drains_unacked_block_before_status() {
    init_env_logger();

    let runner = new_default_runner();
    let server_phase = AtomicUsize::new(0);

    futures_lite::future::block_on(async {
        select(
            runner.run_responder(CancelDownloadWithUnackedBlockHandler(&server_phase)),
            async {
                let mut exchange = runner.initiate_exchange().await?;
                exchange
                    .send_with(|_, wb| {
                        bdx::TransferInit {
                            transfer_control: bdx::TransferControl {
                                version: bdx::BDX_VERSION,
                                sender_drive: true,
                                receiver_drive: true,
                                async_mode: false,
                            },
                            range_control: bdx::RangeControl::default(),
                            max_block_size: 1024,
                            start_offset: 0,
                            length: 0,
                            file_designator: FILE_DESIGNATOR,
                            metadata: &[],
                        }
                        .write(wb)?;
                        Ok(Some(bdx::OpCode::ReceiveInit.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
                assert!(accept.transfer_control.receiver_drive);
                assert!(!accept.transfer_control.sender_drive);
                exchange.rx_done()?;

                exchange
                    .send_with(|_, wb| {
                        bdx::BlockQuery { block_counter: 0 }.write(wb)?;
                        Ok(Some(bdx::OpCode::BlockQuery.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                assert_eq!(exchange.rx()?.meta().proto_opcode, bdx::OpCode::Block as u8);
                let block = bdx::Block::parse(exchange.rx()?.payload())?;
                assert_eq!(block.block_counter, 0);
                assert_eq!(block.data, &[0xA5; 1024]);
                server_phase.store(1, Ordering::Release);

                core::future::poll_fn(|cx| {
                    if server_phase.load(Ordering::Acquire) >= 2 {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                if server_phase.load(Ordering::Acquire) == 4 {
                    return Err(rs_matter::error::ErrorCode::InvalidState.into());
                }

                // `send_with` releases the held block and carries its MRP ACK,
                // while the BDX counter requests a block the cancelled writer
                // must never send.
                exchange.rx_done()?;
                exchange
                    .send_with(|_, wb| {
                        bdx::BlockQuery { block_counter: 1 }.write(wb)?;
                        Ok(Some(bdx::OpCode::BlockQuery.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                let meta = exchange.rx()?.meta();
                assert_eq!(meta.proto_id, rs_matter::sc::PROTO_ID_SECURE_CHANNEL);
                assert_eq!(meta.proto_opcode, ScOpCode::StatusReport as u8);
                let mut rb = ReadBuf::new(exchange.rx()?.payload());
                let report = StatusReport::read(&mut rb)?;
                assert_eq!(report.proto_id, bdx::PROTO_ID_BDX as u32);
                assert_eq!(
                    report.proto_code,
                    bdx::BdxStatus::TransferFailedUnknownError as u16
                );
                assert_eq!(server_phase.load(Ordering::Acquire), 2);
                exchange.rx_done()?;
                exchange.acknowledge().await?;

                with_timeout(async {
                    core::future::poll_fn(|cx| {
                        let phase = server_phase.load(Ordering::Acquire);
                        if phase == 3 || phase == 4 {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    assert_eq!(server_phase.load(Ordering::Acquire), 3);
                    Ok::<_, Error>(())
                })
                .await?;

                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

/// A reliable Query(1) with no stale piggyback ACK can occupy the shared RX
/// buffer while the cancellation StatusReport is waiting for its ACK.
#[test]
fn test_bdx_download_cancel_acks_late_block_query_during_status_report() {
    init_env_logger();

    let runner = new_default_runner();
    let race = E2eLateBdxQueryRace::new();
    let cancelled = AtomicBool::new(false);
    let client_done = AtomicBool::new(false);

    futures_lite::future::block_on(async {
        select(
            async {
                let responder = runner.run_responder_with_late_bdx_query(
                    CancelDownloadWithLateBlockQueryHandler(&cancelled),
                    &race,
                );
                let done = core::future::poll_fn(|cx| {
                    if client_done.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                });
                match select(responder, done).await {
                    Either::First(result) => result,
                    Either::Second(()) => Ok(()),
                }
            },
            async {
                let mut exchange = runner.initiate_exchange().await?;
                exchange
                    .send_with(|_, wb| {
                        bdx::TransferInit {
                            transfer_control: bdx::TransferControl {
                                version: bdx::BDX_VERSION,
                                sender_drive: true,
                                receiver_drive: true,
                                async_mode: false,
                            },
                            range_control: bdx::RangeControl::default(),
                            max_block_size: 1024,
                            start_offset: 0,
                            length: 0,
                            file_designator: FILE_DESIGNATOR,
                            metadata: &[],
                        }
                        .write(wb)?;
                        Ok(Some(bdx::OpCode::ReceiveInit.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                let accept = bdx::TransferAccept::parse(true, exchange.rx()?.payload())?;
                assert!(accept.transfer_control.receiver_drive);
                assert!(!accept.transfer_control.sender_drive);
                exchange.rx_done()?;

                exchange
                    .send_with(|_, wb| {
                        bdx::BlockQuery { block_counter: 0 }.write(wb)?;
                        Ok(Some(bdx::OpCode::BlockQuery.into()))
                    })
                    .await?;

                exchange.recv_fetch().await?;
                assert_eq!(exchange.rx()?.meta().proto_opcode, bdx::OpCode::Block as u8);
                let block = bdx::Block::parse(exchange.rx()?.payload())?;
                assert_eq!(block.block_counter, 0);
                assert_eq!(block.data, &[0xA5; 1024]);
                exchange.rx_done()?;
                exchange.acknowledge().await?;

                race.arm_query();
                {
                    let mut query = core::pin::pin!(exchange.send_with(|_, wb| {
                        bdx::BlockQuery { block_counter: 1 }.write(wb)?;
                        Ok(Some(bdx::OpCode::BlockQuery.into()))
                    }));
                    let injected = core::future::poll_fn(|cx| {
                        if race.query_injected() {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    });

                    match select(query.as_mut(), injected).await {
                        Either::First(result) => result?,
                        Either::Second(()) => {}
                    }
                    assert!(race.query_injected());
                }

                assert!(race.status_report_sent());
                let status_report_retried = core::future::poll_fn(|cx| {
                    if race.status_report_retried() {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                });
                match select(status_report_retried, Timer::after(Duration::from_secs(2))).await {
                    Either::First(()) => {}
                    Either::Second(()) => panic!(
                        "StatusReport was not retransmitted; observed {} sends",
                        race.status_report_attempts()
                    ),
                }
                assert!(race.query_acknowledged());
                assert_ne!(
                    race.query_ack_counter(),
                    race.status_report_counter(),
                    "the Query ACK must use a fresh message counter"
                );
                assert!(race.status_report_retried());
                assert!(race.status_report_retries_identical());
                assert!(race.status_report_attempts() >= 2);
                assert!(race.status_report_reliable());
                assert_eq!(
                    race.status_report_status(),
                    bdx::BdxStatus::TransferFailedUnknownError as u32
                );
                assert!(
                    !race.block_one_sent(),
                    "cancellation must not send BDX Block(1)"
                );
                assert!(
                    !race.block_eof_one_sent(),
                    "cancellation must not send BDX BlockEOF(1)"
                );

                let cancellation = core::future::poll_fn(|cx| {
                    if cancelled.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                });
                match select(cancellation, Timer::after(Duration::from_secs(2))).await {
                    Either::First(()) => {}
                    Either::Second(()) => {
                        panic!("cancellation did not process the ACK queued behind Query(1)")
                    }
                }

                let query_ack_received =
                    core::future::poll_fn(|cx| match exchange.pending_retrans() {
                        Ok(false) => Poll::Ready(Ok(())),
                        Ok(true) => {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Err(error) => Poll::Ready(Err(error)),
                    });
                match select(query_ack_received, Timer::after(Duration::from_secs(2))).await {
                    Either::First(result) => result?,
                    Either::Second(()) => panic!(
                        "client did not consume Query(1) ACK ctr {} (report ctr {})",
                        race.query_ack_counter(),
                        race.status_report_counter()
                    ),
                }

                assert!(!race.block_one_sent());
                assert!(!race.block_eof_one_sent());
                client_done.store(true, Ordering::Release);
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

/// Dropping a pending cancel future still leaves the writer terminal; the abort
/// report already queued on the exchange reaches the peer and no block follows.
#[test]
fn test_bdx_writer_cancel_future_drop_is_terminal() {
    init_env_logger();

    let runner = new_default_runner();
    let report_received = AtomicBool::new(false);

    futures_lite::future::block_on(async {
        select(
            runner.run_responder(WaitForUploadCancelHandler(&report_received)),
            async {
                let exchange = runner.initiate_exchange().await?;
                let mut tx_buf = [0u8; 128];
                let mut writer = exchange
                    .upload(
                        &mut tx_buf,
                        FILE_DESIGNATOR,
                        None,
                        TransferExtent::Definite(12),
                    )
                    .await?;
                assert_eq!(writer.write(b"staged data").await?, 11);

                let cancel_pending = {
                    let mut cancel = core::pin::pin!(writer.cancel());
                    core::future::poll_fn(|cx| match cancel.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(true),
                        Poll::Ready(_) => Poll::Ready(false),
                    })
                    .await
                };
                assert!(cancel_pending, "cancel should wait for the peer ACK");
                assert!(
                    writer.write(b"later data").await.is_err(),
                    "dropping cancel must not re-enable block traffic"
                );

                with_timeout(async {
                    core::future::poll_fn(|cx| {
                        if report_received.load(Ordering::Acquire) {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok::<_, Error>(())
                })
                .await?;
                Ok::<_, Error>(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}
