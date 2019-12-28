#!/bin/bash

sudo apt -y update
sudo apt-get install -y libc6-dev g++-multilib python p7zip-full pwgen jq curl
cd ~

if [ -f cbtc.zip ]
then
    rm cbtc.zip
fi
wget -O cbtc.zip `curl -s 'https://api.github.com/repos/classicbitcoins/cbtc/releases/latest' | jq -r '.assets[].browser_download_url' | egrep "cbtc.+x64.zip"`
7z x -y cbtc.zip
chmod -R a+x ~/cbtc-pkg
rm cbtc.zip

cd ~/cbtc-pkg
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
