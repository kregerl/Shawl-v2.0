use core::time;
use std::{
    io::{Read, Write},
    mem::size_of,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime},
};

use async_minecraft_ping::ConnectionConfig;
use clap::{value_parser, Arg, ArgAction, Command};
use futures::{stream, StreamExt};
use ipnet::{Ipv4AddrRange, Ipv4Net};
use pinger::ping_server;
use rand::{seq::SliceRandom, thread_rng};
use signal_hook::{consts::SIGINT, iterator::Signals};
use tokio::net::TcpStream;
use tokio_postgres::{tls::NoTlsStream, Client, Connection, NoTls, Socket};

mod pinger;

const DEFAULT_PORTS: &[u16] = &[25575, 25564, 25565, 25566];
#[tokio::main]
async fn main() {
    // TODO: Add a 'consecutive' arg to generate ranges consecutively.
    let matches = Command::new("Shawl")
        .version("0.2.0")
        .about("Port scanner searching specifically for open minecraft servers.")
        .subcommand(Command::new("mcp"))
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
        // let client = connect_to_db().await;

        // client.execute("CREATE TABLE IF NOT EXISTS public.minecraft_servers (addr VARCHAR (25) PRIMARY KEY, max_players SMALLINT, players SMALLINT, version_str TEXT, description TEXT, query_time TIMESTAMP)", &[]).await.unwrap();

        // query_scanned_servers(&client, Duration::from_secs(5), 100).await;
    } else {
        let mut ips = vec![];
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

        if let Some(includes) = matches.get_many::<String>("include") {
            let mut x: Vec<Ipv4Net> = includes
                .map(|include| Ipv4Net::from_str(include).unwrap())
                .collect();
            ips.append(&mut x);
        }

        if let (Some(concurrency), Some(timeout)) = (
            matches.get_one::<usize>("concurrency"),
            matches.get_one::<u64>("timeout"),
        ) {
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
    let mut config = ConnectionConfig::build(&ip);
    config = config.with_port(port as u16);
    config = config.with_timeout(timeout);

    let connection = match config.connect().await {
        Ok(conn) => conn,
        Err(_) => {
            println!("Error connecting to Minecraft server");
            return;
        }
    };
    match connection.status().await {
        Ok(ping) => {
            println!("Here: {:#?}", ping.status);
            println!(
                "players: {}/{}",
                ping.status.players.online, ping.status.players.max
            );
            println!("description: {:#?}", ping.status.description);
            println!(
                "version: {} -- {}",
                ping.status.version.name, ping.status.version.protocol
            );
            let description_str = match ping.status.description {
                async_minecraft_ping::ServerDescription::Plain(text) => text,
                async_minecraft_ping::ServerDescription::Object { text } => text,
            };

            client.execute("INSERT INTO public.minecraft_servers(addr, max_players, players, version_str, description, query_time) VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT (addr) DO NOTHING ", 
            &[&format!("{}:{}", &ip, port), &(ping.status.players.max as i16), &(ping.status.players.online as i16), &ping.status.version.name, &description_str]).await.unwrap();
        }
        Err(_) => {
            println!("Error pinging Minecraft server");
            return;
        }
    }
}

async fn query_scanned_servers(client: &Client, timeout: Duration, concurrency: usize) {
    let mut futures = Vec::new();
    let rows = client.query("SELECT op.ip, op.port FROM open_ports op WHERE NOT EXISTS(SELECT FROM minecraft_servers ms WHERE op.addr = ms.addr)", &[]).await.unwrap();
    for row in rows {
        let ip_str: &str = row.get("ip");
        let ip: String = ip_str.into();
        let port: i16 = row.get("port");
        futures.push(attempt_ping_server(&client, ip.clone(), port as u16, timeout));
    }

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
