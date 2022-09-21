use kzg_ceremony_crypto as lib;

fn main() {
    let mut criterion = criterion::Criterion::default()
        .configure_from_args()
        .sample_size(10);
    lib::bench::group(&mut criterion);
    criterion.final_summary();
}
