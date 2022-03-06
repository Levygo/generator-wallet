# Blergh
Multithreaded brute-force BTC wallet generator written in Rust.\
\
Tackling almost all processing power of your pc to waste it on generating random gibberish (BTC keys and addresses),
once in a while it also fetching weird letters from BTC blockchain [API](https://www.blockcypher.com/dev/bitcoin).
Please be mindful abuot our planet and don't waste more energy than is needed. It's just a proof of concept that most likely won't make you any richer than you are.\
**ONLY FOR EDUCATIONAL PURPOSES**


## Features
- single operation (generation + check) takes 40-50μs which is around 20k+ wallets per second in single thread
- Automatic fetching of new wallet addresses from blockchain based on recent transactions
- Supports P2PKH and P2SH address formats

## Usage
    blergh 0.1.1
    Brute-force BTC wallet generator and checker

    USAGE:
        blergh.exe [OPTIONS]

    OPTIONS:
        -c, --cpu-count <CPU_COUNT>
                Number of cpus to use (0-auto) [default: 0]

        -h, --help
                Print help information

        -s, --source-file <SOURCE_FILE>
                Path to file with target addresses [default: addr.txt]

        -u, --update-timeout <UPDATE_TIMEOUT>
                Time (in seconds) to wait between target file updates [default: 600]

        -v, --verbose
                Print wallets while generating

        -V, --version
                Print version information
