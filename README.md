# Smart Contract Program Slicer

Takes any Solidity contract as input, finds external calls, and runs:
- backward slicing
- forward slicing
- variable-at-risk analysis (written-window pattern)

## Usage

```bash
python3 slicer.py <contract.sol> <ContractName>
```

Example:

```bash
python3 slicer.py SimpleBank.sol SimpleBank
```

## Requirements

- Python 3.10+
- Node.js + npm

Install dependencies in a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Install Solidity compiler (using `npx` to avoid global install permission issues):

```bash
npx solc --version
```

If `npx` prompts to install `solc`, type `y`.

## Output

For each external call, the tool prints:
- `BACKWARD SLICE`
- `FORWARD SLICE`
- `VARIABLES AT RISK`

## Notes

- Current risk reporting focuses on the **written-window** reentrancy pattern.
- Stale-value reporting is currently disabled to avoid false positives.
