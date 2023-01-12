use std::{
    io::{Write, BufReader, BufRead},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration, fs::File, collections::HashSet,
};

use clap::{value_parser, Arg, ArgAction, Command};
use futures::{stream, StreamExt};
use ipnet::Ipv4Net;
use pinger::ping_server;
use rand::{seq::SliceRandom, thread_rng};
use tokio::net::TcpStream;
use tokio_postgres::{Client, NoTls};

mod pinger;

const DEFAULT_PORTS: &[u16] = &[25575, 25564, 25565, 25566];
#[tokio::main]
async fn main() {
    // TODO: Add a 'consecutive' arg to generate ranges consecutively.
    let matches = Command::new("Shawl")
        .version("0.2.0")
        .about("Port scanner searching specifically for open minecraft servers.")
        .subcommand(Command::new("mcp"))
        .arg(Arg::new("from-file").long("from-file").required(false))
        .arg(
            Arg::new("include")
                .short('i')
                .long("include")
                .required(false)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .required(false)
                .value_parser(value_parser!(u64))
                .default_value("5"),
        )
        .arg(
            Arg::new("concurrency")
                .short('c')
                .long("concurrency")
                .required(false)
                .value_parser(value_parser!(usize))
                .default_value("2000"),
        )
        .arg(
            Arg::new("randoms")
                .short('r')
                .long("max-randoms")
                .required(false)
                .value_parser(value_parser!(usize)),
        )
        .get_matches();

    if let Some(_) = matches.subcommand_matches("mcp") {
        let client = connect_to_db().await;

        client.execute("CREATE TABLE IF NOT EXISTS public.minecraft_servers (addr VARCHAR (25) PRIMARY KEY, max_players INTEGER, players INTEGER, version_str TEXT, protocol_version INTEGER, description TEXT, query_time TIMESTAMP)", &[]).await.unwrap();

        client.execute("CREATE TABLE IF NOT EXISTS public.confirmed_not_minecraft_servers (addr VARCHAR (25) PRIMARY KEY, error TEXT)", &[]).await.unwrap();

        query_scanned_servers(&client, Duration::from_secs(8), 1000).await;
    } else {
        let mut ips;
        if let Some(n) = matches.get_one::<usize>("randoms") {
            ips = generate_random_ranges()[..*n].to_vec();
        } else {
            ips = generate_random_ranges();
        }
        println!(
            "Generated {} ip address ranges totaling {}mb",
            ips.len(),
            (ips.len() * 5) / 1000
        );

        if let Some(file_name) = matches.get_one::<String>("from-file") {
            let file = File::open(file_name).unwrap();
            let lines = BufReader::new(file).lines();
            let mut set : HashSet<String> = HashSet::new();

            for line in lines {
                set.insert(line.unwrap());
            }
            println!("Found {} unique ip ranges in file {}", set.len(), file_name);
            let mut ranges = set.into_iter().map(|entry| Ipv4Net::from_str(&entry).unwrap()).collect::<Vec<Ipv4Net>>();
            ips.append(&mut ranges);
        }

        if let Some(includes) = matches.get_many::<String>("include") {
            let mut x: Vec<Ipv4Net> = includes
                .map(|include| Ipv4Net::from_str(include).unwrap())
                .collect();
            ips.append(&mut x);
        }

        // Unwraps are safe here since the args have a default value.
        let (concurrency, timeout) = (
            matches.get_one::<usize>("concurrency").unwrap(),
            matches.get_one::<u64>("timeout").unwrap(),
        );

        let client = connect_to_db().await;

        client.execute("CREATE TABLE IF NOT EXISTS public.open_ports (addr VARCHAR (25) PRIMARY KEY, ip VARCHAR (15), port SMALLINT)", &[]).await.unwrap();
        client
            .execute(
                "CREATE TABLE IF NOT EXISTS public.scanned_ports (addr VARCHAR (25) PRIMARY KEY)",
                &[],
            )
            .await
            .unwrap();
        println!("Starting Shawl...");
        scan_multiple_targets(client, &ips, *concurrency, *timeout, DEFAULT_PORTS).await;
    }
}

async fn scan_multiple_targets(
    client: Client,
    ip_range: &[Ipv4Net],
    concurrency: usize,
    timeout: u64,
    ports: &[u16],
) {
    let mut futures = Vec::new();
    for range in ip_range {
        futures.push(scan_host_range(&client, range, ports, concurrency, timeout));
    }

    println!("Streaming multiple targets");
    stream::iter(futures)
        .buffer_unordered(concurrency)
        .collect::<()>()
        .await;
}

async fn scan_host_range(
    client: &Client,
    ip_range: &Ipv4Net,
    ports: &[u16],
    concurrency: usize,
    timeout: u64,
) {
    stream::iter(ip_range.hosts())
        .for_each_concurrent(concurrency, |addr| {
            scan_target_ports(&client, IpAddr::V4(addr), ports, concurrency, timeout)
        })
        .await;

    println!(
        "Scanned IP Range: {}/{}",
        ip_range.addr(),
        ip_range.prefix_len()
    );

    client
        .execute(
            "INSERT INTO public.scanned_ports(addr) VALUES ($1) ON CONFLICT (addr) DO NOTHING",
            &[&ip_range.to_string()],
        )
        .await
        .unwrap();
}

async fn scan_target_ports(
    client: &Client,
    target_ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
    timeout: u64,
) {
    let addrs = stream::iter(
        ports
            .iter()
            .map(|port| scan_target(target_ip, *port, timeout)),
    )
    .buffer_unordered(concurrency)
    .collect::<Vec<Option<SocketAddr>>>()
    .await;

    for addr in addrs {
        if let Some(address) = addr {
            println!("Found open port at addr: {}", address);
            client
                .execute(
                    "INSERT INTO public.open_ports(addr, ip, port) VALUES ($1, $2, $3) ON CONFLICT (addr) DO NOTHING",
                    &[
                        &address.to_string(),
                        &address.ip().to_string(),
                        &(address.port() as i16),
                    ],
                )
                .await
                .unwrap();
        }
    }
}

async fn scan_target(target_ip: IpAddr, port: u16, timeout_secs: u64) -> Option<SocketAddr> {
    let timeout = Duration::from_secs(timeout_secs);
    let socket_addr = SocketAddr::new(target_ip.clone(), port);

    // println!("Scanning {}", socket_addr);
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_)) => Some(socket_addr),
        _ => None,
    }
}

async fn connect_to_db() -> Client {
    let mut user = String::new();
    print!("Enter your postgresql username: ");
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin()
        .read_line(&mut user)
        .expect("Unable to read line ");
    print!("Enter your postgresql password: ");
    std::io::stdout().flush().unwrap();
    let password = rpassword::read_password().unwrap();

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host=loucaskreger.com user={} password={} dbname=scanner",
            user, password
        ),
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection Error: {}", e);
        }
    });
    client
}

async fn attempt_ping_server(client: &Client, ip: String, port: u16, timeout: Duration) {
    match ping_server(&ip, port, timeout).await {
        Ok(status) => {
            let description_str = match status.description {
                pinger::Description::Plain(text) => text,
                pinger::Description::ChatObject { text } => text,
            };

            println!("Got minecraft server: {}:{}", ip, port);

            client.execute("INSERT INTO public.minecraft_servers(addr, max_players, players, version_str, protocol_version, description, query_time) VALUES ($1, $2, $3, $4, $5, $6, now()) ON CONFLICT (addr) DO NOTHING ", 
            &[&format!("{}:{}", &ip, port), &status.players.max, &status.players.online, &status.version.name, &status.version.protocol, &description_str]).await.unwrap();
        }
        Err(error) => {
            println!("Error: {}", error.to_string());
            client.execute("INSERT INTO public.confirmed_not_minecraft_servers(addr, error) VALUES ($1, $2) ON CONFLICT (addr) DO NOTHING", &[&format!("{}:{}", ip, port), &error.to_string()]).await.unwrap();
            return;
        }
    }
}

async fn query_scanned_servers(client: &Client, timeout: Duration, concurrency: usize) {
    let mut futures = Vec::new();
    let rows = client.query("SELECT op.ip, op.port FROM open_ports op WHERE NOT EXISTS(SELECT FROM minecraft_servers ms WHERE op.addr = ms.addr)", &[]).await.unwrap();
    println!("Got {} rows", rows.len());
    for row in rows {
        let ip_str: &str = row.get("ip");
        let ip: String = ip_str.into();
        let port: i16 = row.get("port");
        futures.push(attempt_ping_server(
            &client,
            ip.clone(),
            port as u16,
            timeout,
        ));
    }

    println!("Streaming...");
    stream::iter(futures)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
}

// TODO: Insert generated octets into db and ignore them if they've been used before.
/// Generates a random range of Ip addresses in /16 cidr notation.
fn generate_random_ranges() -> Vec<Ipv4Net> {
    let mut first: Vec<u8> = (1..=0xFF).collect();
    let mut second: Vec<u8> = (1..=0xFF).collect();
    first.shuffle(&mut thread_rng());
    second.shuffle(&mut thread_rng());

    let mut ranges = Vec::new();
    for a in first {
        for b in &second {
            let net = Ipv4Net::from_str(&format!("{0}.{1}.0.0/16", a, b)).unwrap();
            ranges.push(net);
        }
    }
    ranges.shuffle(&mut thread_rng());
    ranges
}
