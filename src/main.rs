mod config;
mod scan;

use env_logger;
use log::debug;

fn main() {
    env_logger::init();

    let flags = config::Flags::init();
    debug!("{:?}", flags);
    let config: config::Config = flags.into();
    debug!("{:?}", config);

    scan::run(config);
}
