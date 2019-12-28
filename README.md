=======
# CBTC
**Keep running wallet to strengthen the CBTC network. Backup your wallet in many locations & keep your coins wallet offline.**

### Ports:
- RPC port: 2051
- P2P port: 2050

Install
-----------------
### Linux

### [Quick guide for beginners](https://github.com/cbtc-pod/cbtc/wiki/Quick-guide-for-beginners)

Install required dependencies:
```{r, engine='bash'}
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake
```

Execute the build command:
```{r, engine='bash'}
# Clone CBTC Repository
git clone https://github.com/classicbitcoins/cbtc
# Build
cd cbtc/
./zcutil/build.sh -j$(nproc)
# fetch key
./zcutil/fetch-params.sh
```

Usage:
```{r, engine='bash'}
# Run
./src/cbtcd
# Test getting information about the network
cd src/
./cbtc-cli getmininginfo
# Test creating new transparent address
./cbtc-cli getnewaddress
# Test creating new private address
./cbtc-cli z_getnewaddress
# Test checking transparent balance
./cbtc-cli getbalance
# Test checking total balance 
./cbtc-cli z_gettotalbalance
# Check all available wallet commands
./cbtc-cli help
# Get more info about a single wallet command
./cbtc-cli help "The-command-you-want-to-learn-more-about"
./cbtc-cli help "getbalance"
```

### Windows
The CBTC Windows Command Line Wallet can only be built from ubuntu for now.

Install required dependencies:
```
apt-get update \
&& apt-get install -y \
    curl build-essential pkg-config libc6-dev m4 g++-multilib autoconf \
    libtool ncurses-dev unzip git python zlib1g-dev wget bsdmainutils \
    automake p7zip-full pwgen mingw-w64 cmake
```

Execute the build command:
```
./zcutil/build-win.sh -j$(nproc)
```

### Docker

Build
```
$ docker build -t cbtc/cbtc .
```

Create a data directory on your local drive and create a cbtc.conf config file
```
$ mkdir -p /ops/volumes/cbtc/data
$ touch /ops/volumes/cbtc/data/cbtc.conf
$ chown -R 999:999 /ops/volumes/cbtc/data
```

Create cbtc.conf config file and run the application
```
$ docker run -d --name cbtc-node \
  -v cbtc.conf:/cbtc/data/cbtc.conf \
  -p 2050:2050 -p 127.0.0.1:2051:2051 \
  cbtc/cbtc
```

Verify cbtc-node is running
```
$ docker ps
CONTAINER ID        IMAGE                  COMMAND                     CREATED             STATUS              PORTS                                              NAMES
31868a91456d        cbtc/cbtc          "cbtcd --datadir=..."   2 hours ago         Up 2 hours          127.0.0.1:2051->2051/tcp, 0.0.0.0:2050->2050/tcp   cbtc-node
```

Follow the logs
```
docker logs -f cbtc-node
```

The cli command is a wrapper to cbtc-cli that works with an already running Docker container
```
docker exec -it cbtc-node cli help
```

## Using a Dockerfile
If you'd like to have a production btc/cbtc image with a pre-baked configuration
file, use of a Dockerfile is recommended:

```
FROM cbtc/cbtc
COPY cbtc.conf /cbtc/data/cbtc.conf
```

Then, build with `docker build -t my-cbtc .` and run.

### Windows
Windows build is maintained in [cbtc-win project](https://github.com/cbtc-pod/cbtc-win).

Security Warnings
-----------------

**CBTC is experimental and a work-in-progress.** Use at your own risk.
