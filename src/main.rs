use std::env;

fn main() {
    if let Err(err) =
        topo::core::app::run::<topo::protocol::Protocol>(env::args().skip(1).collect())
    {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
