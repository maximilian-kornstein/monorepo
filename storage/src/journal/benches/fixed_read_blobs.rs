use crate::{PAGE_CACHE_SIZE, PAGE_SIZE, REPLAY_BUFFER, WRITE_BUFFER, append_fixed_random_data};
use commonware_bench::Inputs;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context, Runner},
};
use commonware_storage::journal::contiguous::{
    Contiguous as _,
    fixed::{Config as FixedConfig, Journal},
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes, test_rng};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

/// Partition name to use in the journal config.
const PARTITION: &str = "test-partition";

/// Small blobs, so random reads spread across many of them.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_000);

/// Size of each journal item in bytes.
const ITEM_SIZE: usize = 32;

/// Number of random reads per iteration.
const READS: usize = 10_000;

/// Number of blobs in the journal read from.
fn blobs() -> u64 {
    match Inputs::current() {
        Inputs::Smoke => 10,
        _ => 1_000,
    }
}

/// Limits on open sealed blobs to compare, `None` keeping every blob open.
fn max_open() -> &'static [Option<NonZeroUsize>] {
    match Inputs::current() {
        Inputs::Smoke => &[None, Some(NZUsize!(4))],
        _ => &[
            None,
            Some(NZUsize!(16)),
            Some(NZUsize!(256)),
            Some(NZUsize!(1_024)),
        ],
    }
}

/// Open the journal with at most `max_open_blobs` sealed blobs open.
async fn open(
    context: Context,
    max_open_blobs: Option<NonZeroUsize>,
) -> Journal<Context, FixedBytes<ITEM_SIZE>> {
    let cfg = FixedConfig {
        partition: PARTITION.into(),
        items_per_blob: ITEMS_PER_BLOB,
        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
        max_open_blobs,
    };
    Journal::init(context, cfg).await.unwrap()
}

/// Read `READS` uniformly random items, awaiting each before the next.
async fn read_random(journal: &Journal<Context, FixedBytes<ITEM_SIZE>>, items: u64) {
    let mut rng = test_rng();
    for _ in 0..READS {
        let pos = rng.random_range(0..items);
        black_box(journal.read(pos).await.expect("failed to read data"));
    }
}

/// Benchmark random reads across many blobs for several limits on open blobs.
fn bench_fixed_read_blobs(c: &mut Criterion) {
    let cfg = Config::default();
    let items = blobs() * ITEMS_PER_BLOB.get();
    let mut initialized = false;
    let runner = tokio::Runner::new(cfg.clone());
    for &max_open in max_open() {
        let limit = max_open.map_or_else(|| "unbounded".to_string(), |n| n.to_string());
        c.bench_function(
            &format!(
                "{}/max_open={limit} blobs={} reads={READS} size={ITEM_SIZE}",
                module_path!(),
                blobs(),
            ),
            |b| {
                // Setup: populate the journal once, on the first selected benchmark.
                if !initialized {
                    Runner::new(cfg.clone()).start(|context| async move {
                        let journal = open(context, None).await;
                        append_fixed_random_data::<_, ITEM_SIZE>(journal, items).await;
                    });
                    initialized = true;
                }

                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let journal = open(ctx.child("storage"), max_open).await;
                    let mut duration = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        read_random(&journal, items).await;
                        duration += start.elapsed();
                    }
                    duration
                });
            },
        );
    }

    if initialized {
        Runner::new(cfg).start(|context| async move {
            open(context, None).await.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_read_blobs
}
