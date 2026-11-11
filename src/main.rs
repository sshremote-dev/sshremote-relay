mod hub;

const USAGE: &str = "sshremote-relay [--listen ADDR] [--store FILE]

  --listen ADDR   where to listen (default 0.0.0.0:7071)
  --store FILE    keep which token owns each ID here, so IDs survive restarts";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).map(String::as_str);
    if let Err(e) = hub::serve(get("--listen").unwrap_or("0.0.0.0:7071"), get("--store")) {
        eprintln!("sshremote-relay: {e}");
        std::process::exit(1);
    }
}
