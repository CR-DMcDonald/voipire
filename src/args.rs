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

const RTP_PORT_RANGE_START: u16 = 16384;
const RTP_PORT_RANGE_END: u16 = 32767;

#[derive(Clone)]
pub struct Args {
    pub host: IpAddr,
    pub port_range: (u16, u16),
    pub output_file: String,
    pub max_threads: u8,
}

use std::net::IpAddr;  

impl Args {
    pub fn new() -> Result<Args,()> {

        //get a vector of the command line arguments
        let mut args: Vec<String> = std::env::args().collect();
        
        //is one of the arguements -h?
        let host: IpAddr = if args.contains(&String::from("-h")) {
            //get the index of the -h arguement
            let index = args.iter().position(|r| r == "-h").unwrap();
            //get the next arguement
            let host = &args[index + 1].clone();

            //remove the used arguements
            args.remove(index);
            args.remove(index);

            //parse the host into an IpAddr, check if it is valid
            match host.parse() {
                Ok(host) => host,
                Err(_) => {
                    println!("Invalid host specified, use -h <host>");
                    return Err(());
                }
            }
        } else {
            //if -h is not present, panic
            println!("No host specified, use -h <host>");
            return Err(());
        };

        //is one of the arguements -p?
        let port_range: (u16, u16) = if args.contains(&String::from("-p")) {
            //get the index of the -p arguement
            let index = args.iter().position(|r| r == "-p").unwrap();

            //is there at least one argument after?
            if args.len() < index + 2 {
                println!("No port specified, use -p <port>");
                return Err(());
            }

            //get the next arguement
            let port = &args[index + 1].clone();

            //remove the used arguements
            args.remove(index);
            args.remove(index);

            if port.contains("-") {
                //if the port contains a range, split it
                let port_range: Vec<&str> = port.split("-").collect();
                (port_range[0].parse().unwrap(), port_range[1].parse().unwrap())
            } else {
                //parse the port into a tuple of u8
                (port.parse().unwrap(), port.parse().unwrap())
            }
        } else {
            //if -p is not present, use the default port range
            (RTP_PORT_RANGE_START, RTP_PORT_RANGE_END)
        };

        let output_file = if args.contains(&String::from("-o")) {
            //get the index of the -o arguement
            let index = args.iter().position(|r| r == "-o").unwrap();
            //get the next arguement
            let output_file = &args[index + 1].clone();
            //remove the used arguements
            args.remove(index);
            args.remove(index);
            output_file.clone()
        } else {
            //create a default output file in the form scan-<host>-<datestamp>.raw
            let date = chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S").to_string();
            format!("scan-{}-{}", host, date)
        };

        //is one of the arguements -t?
        let max_threads: u8 = if args.contains(&String::from("-t")) {
            //get the index of the -t arguement
            let index = args.iter().position(|r| r == "-t").unwrap();
            //get the next arguement
            let max_threads = &args[index + 1].clone();
            //remove the used arguements
            args.remove(index);
            args.remove(index);
            max_threads.parse().unwrap()
        } else {
            //use the default number of threads
            8
        };

        //if there are any unused arguements, print the usage and exit
        if args.len() > 1 {
            usage();
            std::process::exit(1);
        }

        Ok(Args {
            host,
            port_range,
            output_file,
            max_threads,
        })
    }
}

pub fn usage() {
    println!("Example usage");
    println!("Scan the RTP default ports");
    println!("  ./voipire -h 1.2.3.4");
    println!("Scan just one port");
    println!("  ./voipire -h 1.2.3.4 -p 18554");
    println!("");
    println!("Scan a range of ports");
    println!("  ./rtpbleedscan -h 1.2.3.4 -p 18554-18560");
    println!("");
    println!("Specify max threads");
    println!("  ./rtpbleedscan -h 1.2.3.4 -p 18554-18560 -t 8");
    println!("");
    println!("Specify output file");
    println!("  ./rtpbleedscan -h 1.2.3.4 -p 18554-18560 -o output.raw");
    println!("");

    println!("-h <host> - The host or ip address to scan");
    println!("-p <port> - The port or range of ports to scan, e.g. 18554 or 18554-18560");
    println!("-t <threads> - The number of threads to use, default is 8");
    println!("-o <output file> - The prefix of the output files write the raw output to, default is scan-<host>-<date>");
}

pub fn banner() {
    println!("🩸🩸 VOIPIRE v0.1 🩸🩸");
    println!("");
    println!("A tool to scan and exploit RTP Bleed in SBCs");
    println!("Written by Darren McDonald, Cryptic Red Ltd");
    println!("Copyright 2024");
    println!("");
}