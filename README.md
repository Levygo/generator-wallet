# Blergh
Multithreaded brute-force BTC wallet generator written in Rust.
Tackling almost all processing power of your pc to waste it on generating random gibberish called BTC keys and addresses, 
once in a while it also gets some weird letters from BTC blockchain [API](https://www.blockcypher.com/dev/bitcoin)
**ONLY FOR EDUCATIONAL PURPOSES**


## Features
- single operation(generation + check) takes 40-50μs which accounts to around 23k wallets per second
- Automatic fetching of new wallet addresses from blockchain based on recent transactions

