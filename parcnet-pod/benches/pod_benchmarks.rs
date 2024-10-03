use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::BigInt;
use parcnet_pod::pod::pod::{create_pod, PodValue};

fn benchmark_create_pod(c: &mut Criterion) {
    let private_key = vec![0u8; 32];

    c.bench_function("create small pod", |b| {
        b.iter(|| {
            create_pod(
                black_box(&private_key),
                black_box(vec![
                    ("name".to_string(), PodValue::String("John Doe".to_string())),
                    ("age".to_string(), PodValue::Int(30)),
                ]),
            )
        })
    });

    c.bench_function("create medium pod", |b| {
        b.iter(|| {
            create_pod(
                black_box(&private_key),
                black_box(vec![
                    ("attack".to_string(), PodValue::Int(7)),
                    (
                        "itemSet".to_string(),
                        PodValue::String("celestial".to_string()),
                    ),
                    (
                        "pod_type".to_string(),
                        PodValue::String("item.weapon".to_string()),
                    ),
                    (
                        "weaponType".to_string(),
                        PodValue::String("sword".to_string()),
                    ),
                    ("durability".to_string(), PodValue::Int(100)),
                ]),
            )
        })
    });

    c.bench_function("create large pod", |b| {
        b.iter(|| {
            create_pod(
                black_box(&private_key),
                black_box(vec![
                    ("id".to_string(), PodValue::String("12345".to_string())),
                    (
                        "name".to_string(),
                        PodValue::String("Excalibur".to_string()),
                    ),
                    ("type".to_string(), PodValue::String("sword".to_string())),
                    (
                        "rarity".to_string(),
                        PodValue::String("legendary".to_string()),
                    ),
                    ("attack".to_string(), PodValue::Int(100)),
                    ("defense".to_string(), PodValue::Int(50)),
                    ("durability".to_string(), PodValue::Int(1000)),
                    ("weight".to_string(), PodValue::Int(5)),
                    ("value".to_string(), PodValue::Int(10000)),
                    (
                        "enchanted".to_string(),
                        PodValue::String("true".to_string()),
                    ),
                    ("element".to_string(), PodValue::String("holy".to_string())),
                    (
                        "cryptoHash".to_string(),
                        PodValue::Cryptographic(BigInt::from(1234567890)),
                    ),
                ]),
            )
        })
    });
}

criterion_group!(benches, benchmark_create_pod);
criterion_main!(benches);
