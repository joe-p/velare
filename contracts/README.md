# ConfidentialTransactions

This is an Algorand smart contract project using Puya TypeScript.

## Prerequisites

- Node.js 18+ and npm
- [AlgoKit CLI](https://github.com/algorandfoundation/algokit-cli) (for local network testing)

## Setup

```bash
npm install
```

## Build

```bash
npm run build
```

This will:

1. Compile the Algorand smart contracts (puya-ts)
2. Generate TypeScript clients for the contracts

## Test

```bash
npm test
```

Tests run against the Algorand LocalNet. Make sure you have AlgoKit running:

```bash
algokit localnet start
```

## Project Structure

- `contracts/` - Smart contract source files (.algo.ts)
- `src/` - Application source code that uses the contracts
- `scripts/` - Build scripts
- `__test__/` - Test files

## Available Scripts

- `npm run build:contracts` - Compile smart contracts only
- `npm run build:clients` - Generate TypeScript clients only
- `npm run build` - Full build (contracts + clients)
- `npm test` - Run tests
- `npm run bt` - Build and test

## Smart Contract

The template includes a simple `Confidentialtransactions` contract that returns "Hello, world!". Check `contracts/Confidentialtransactions.algo.ts` for the contract implementation.

## License

MIT
