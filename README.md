# solana-vanity-keypair-cpu

A CPU-based Solana vanity address generator with Rust backend and Python bindings.

## Prerequisites

- Rust (latest stable)
- Python 3.7+
- pip
- git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/solana-vanity-keypair-cpu.git
cd solana-vanity-keypair-cpu
```

2. Create and activate a Python virtual environment (recommended):
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
```

3. Build and install the package:
```bash
pip install maturin
maturin develop
```

## Usage

Run the test script to verify installation:
```bash
python test.py
```

## Development

To rebuild after making changes to Rust code:
```bash
maturin develop
```

## License

[Add your license information here]
