#!/bin/bash

sudo apt -y update
sudo apt-get install -y libc6-dev g++-multilib python p7zip-full pwgen jq curl
cd ~

if [ -f cbitcoin.zip ]
then
    rm cbitcoin.zip
fi
wget -O cbitcoin.zip `curl -s 'https://api.github.com/repos/classicbitcoins/cbitcoin/releases/latest' | jq -r '.assets[].browser_download_url' | egrep "cbitcoin.+x64.zip"`
7z x -y cbitcoin.zip
chmod -R a+x ~/cbitcoin-pkg
rm cbitcoin.zip

cd ~/cbitcoin-pkg
./fetch-params.sh

if ! [[ -d ~/.cbtc ]]
then
    mkdir -p ~/.cbtc
fi

if ! [[ -f ~/.cbtc/cbtc.conf ]]
then
    echo "rpcuser=rpc`pwgen 15 1`" > ~/.cbtc/cbtc.conf
    echo "rpcpassword=rpc`pwgen 15 1`" >> ~/.cbtc/cbtc.conf
fi

./cbtcd
