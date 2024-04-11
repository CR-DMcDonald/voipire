## voipire

#### Summary

Voipire scans and exploits the RTP bleed vulnerability.

![Screenshot](/images/screenshot1.png "Screenshot")

#### Warning

This exploit can cause signficant disruption on a vulnerable SBC. Use with authorisation of the system owner and care.

#### Supported Systems

This tool might work on Windows and MacOSX but has only been tested by the author on Linux.

#### Installing and Compiling

The application is written in rust and compiles to a stand alone executable.

Setup the rust compile and cargo, then run following command in the root directory of the tool.

<blockquote>cargo build --release</blockquote>

You can then find the executable under target/release/voipire.

#### Processing the raw audio files

The program outputs raw RTP data to .raw files as it finds RTP steams. You'll need to use another tool to open and play these.

Usually the following works. Open Audicity and go File -> Input -> Raw Data...

The encoding will porbably be ULAW or ALAW, Sample Rate 8000hz, and Channels 1. If you get random noise, the stream may be encrypted.