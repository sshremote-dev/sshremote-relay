mod hub;
mod link;

const USAGE: &str = "sshremote-relay [--listen ADDR] [--store FILE]

  --listen ADDR   where to listen (default 0.0.0.0:7071)
  --store FILE    keep which token owns each ID here, so IDs survive restarts
  --key FILE      the relay's lasting key (made there the first time; default: beside the
                  store, or sshremote-relay.key here): computers that seal their line to the
                  relay know it by this, so it must stay the same";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).map(String::as_str);
    if let Err(e) = hub::serve(get("--listen").unwrap_or("0.0.0.0:7071"), get("--store"), get("--key")) {
        eprintln!("sshremote-relay: {e}");
        std::process::exit(1);
    }
}
