#!/bin/sh
mkdir ~/bin ; cargo build --release && cp target/release/filecryption ~/bin
