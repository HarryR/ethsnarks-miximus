# Miximus

[![Build Status](https://travis-ci.org/HarryR/ethsnarks-miximus.svg?branch=master)](https://travis-ci.org/HarryR/ethsnarks-miximus)

Miximus is a self-service coin mixer and anonymous transfer method for Ethereum, it accepts deposits of 1 ETH, then allows you to withdraw coins by providing a zkSNARK proof that proves you know the spend key for one unspent coin without revealing which one it is.

For more information, see:

 * [Miximus.sol](solidity/contracts/Miximus.sol)
 * [miximus.py](python/miximus.py)
 * [test_miximus.py](python/test/test_miximus.py)
 * [miximus.cpp](circuit/miximus.cpp)

The zkSNARK prover is built as a native library which can plug-in to your application, when provided with the correct arguments it returns the zkSNARK proof as JSON. While you may think of zkSNARKs as being slow - the algorithms chosen for Miximus mean proofs can be made in 5 seconds, however we're still studying their security properties.

## Building

Type `make` - the first time you run it will retrieve submodules, setup cmake and build everything, for more information about the build process see the [Travis-CI build logs](https://travis-ci.org/HarryR/ethsnarks-miximus).

Before building, you may need to retrieve the source code for the dependencies:

	git submodule update --init --recursive

The following dependencies (for Linux) are needed:

 * cmake 3
 * g++ or clang++
 * gmp
 * libcrypto
 * boost
 * npm / nvm

For CentOS / Amazon:

```
yum install cmake3 boost-devel gmp-devel
nvm install --lts
make -C ethsnarks python-dependencies
make CMAKE=cmake3
```

## Maintainers

[@HarryR](https://github.com/HarryR)
