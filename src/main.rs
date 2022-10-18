use cli_batteries::version;
use kzg_ceremony_sequencer::async_main;
use opentelemetry::{global, sdk::export::trace::stdout::PipelineBuilder};

#[allow(dead_code)] // Entry point
fn main() {
    // Install OpenTelemetry tracer to enable trace ids
    PipelineBuilder::default()
        .with_writer(std::io::sink())
        .install_simple();

    cli_batteries::run(version!(crypto, small_powers_of_tau), async_main);

    // For completeness only. Currently we are not exporting otlp spans anyway
    global::shutdown_tracer_provider();
}
