#!/bin/sh
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Make sure autoconf is installed
which autoreconf > /dev/null || (echo "Please install autoconf: sudo apt-get install autoconf" && exit 1)

# Autotoolize base directory
autoreconf --no-recursive --install --force --warnings=all

# Download submodules
git submodule init
git submodule sync --recursive
git submodule update --recursive --force --remote

# autogen submodules
cd src/univalue && ./autogen.sh
cd ../secp256k1 && ./autogen.sh
cd ../tor && ./autogen.sh
cd ..