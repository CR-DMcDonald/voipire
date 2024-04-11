// Copyright (C) 2024 Cryptic Red Ltd
// This file is part of voipire <https://github.com/CR-DMcDonald/voipire>.
//
// voipire is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// voipire is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with voipire.  If not, see <http://www.gnu.org/licenses/>.
//
// Written by Darren McDonald

use std::{io::Write, sync::Arc};
use std::net::UdpSocket;

use indicatif::{ProgressBar, ProgressStyle};

mod args;
use args::{banner, Args};

#[tokio::main]
async fn main() {
    banner();
    // Parse the command line arguements
    let args = Args::new();
    match args {
        Ok(args) => {
            // Print the host and port range
            println!("Host: {}", args.host);
            if args.port_range.0 == args.port_range.1 {
                println!("Port: {}", args.port_range.0);
            } else {
                println!("Port Range: {}-{}", args.port_range.0, args.port_range.1);
            }

            println!("");

            // create a vec of ports to scan
            let mut ports: Vec<u16> = (args.port_range.0..args.port_range.1).collect();
            ports.reverse(); //reverse the vector as many SBCs use lower ports first

            // create a progress bar
            let pb = Arc::new(ProgressBar::new(ports.len() as u64));
            pb.set_style(ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ports scanned")
                .unwrap()
                .progress_chars("#>-"));

            loop {
                // create a vector of ports to scan in this batch
                if ports.len() == 0 {
                    pb.finish_with_message("Scanning complete");
                    break;
                }
                let mut batch: Vec<u16> = Vec::new();
                //pop off and store the first max_threads ports, or less if there arnt enough ports
                for _ in 0..args.max_threads {
                    match ports.pop() {
                        Some(port) => {
                            batch.push(port);
                        },
                        None => {
                            break;
                        }
                    }
                }

                //create a vec to store the threads
                let mut threads: Vec<tokio::task::JoinHandle<()>> = Vec::new();

                //next spawn one thread for each port in the batch
                for port in batch {
                    let args = args.clone();
                    let pb = pb.clone();
                    pb.tick();

                    let thread = tokio::spawn(async move {
                        rtp_scan(&args, port);
                        pb.inc(1);
                    });
                    threads.push(thread);
                }

                //wait for all threads to complete
                for thread in threads {
                    thread.await.unwrap();
                }                   
            }


        },
        Err(_) => {
            std::process::exit(1);
        }
    }
}

const MAX_UDP_PACKET_SIZE: usize = 65507;

fn rtp_scan( args: &Args, port : u16) {

    //create a 16 byte array to store the packet and zero it out
    let mut packet: [u8; 12] = [0; 12];

    packet[0] = 0x80;
    packet[1] = 0x80;

    let socket = UdpSocket::bind("0.0.0.0:0");

    let socket = match socket {
        Ok(socket) => socket,
        Err(_) => {
            panic!("Failed to bind to port");
        }
    };

    //create a buffer to store the response
    let mut buffer = [0; MAX_UDP_PACKET_SIZE];

    //create SocketAddr from the target
    let target = format!("{}:{}", &args.host, &port);

    //send the packet to the target, wait 3 seconds for a response and notify the user if something is found
    let result = socket.send_to(&packet, &target);

    match result {
        Ok(result) => result,
        Err(_) => {
            panic!("Failed to send packet");
        }
    };

    //wait 4 seconds for a response from the target
    let _ = socket.set_read_timeout(Some(std::time::Duration::new(4, 0)));

    //read the response
    let result = socket.recv_from(&mut buffer);
    let result = match result {
        Ok(result) => result,
        Err(_) => {
            //close socket and move on to the next port
            return;
        }
    };

    println!("Found something on port: {}:{}", args.host, port);

    //open a file to write the results to
    let filename = format!("{}-{}.raw", &args.output_file, &port);
    let mut file = match std::fs::File::create(filename) {
        Ok(file) => file,
        Err(_) => {
            panic!("{}", format!("Failed to open file {}", args.output_file));
        }
    };

    //write the response to the file
    match file.write_all(&buffer[12..result.0]) {
        Ok(_) => {},
        Err(_) => {
            panic!("Failed to write to file");
        }
    };

    // Switch to non-blocking mode for subsequent operations
    socket.set_nonblocking(true).expect("Failed to set socket to non-blocking");

    //for ten seconds continue to send the packet to the target and writing the response to the file
    let start = std::time::Instant::now();
    loop {
        //pause for 0.1 seconds
        std::thread::sleep(std::time::Duration::from_millis(10));

        if start.elapsed().as_secs() > 10 {
            break;
        }

        if socket.send_to(&packet, &target).is_err() {
            panic!("Failed to send packet");
        }

        let result = socket.recv_from(&mut buffer);
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                continue
            }
        };

        //if the data starts with 0x80, it is likely an RTP packet, skip
        if buffer[0] != 0x80 {
            continue;
        }

        //skip first 12 bytes of the packet and write to disk
        match file.write_all(&buffer[12..result.0]) {
            Ok(_) => {},
            Err(_) => {
                panic!("Failed to write to file");
            }
        };
    }        


}
