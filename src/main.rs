use cli_batteries::version;
use kzg_ceremony_sequencer::async_main;

#[allow(dead_code)] // Entry point
fn main() {
    cli_batteries::run(version!(crypto, small_powers_of_tau), async_main);
}
