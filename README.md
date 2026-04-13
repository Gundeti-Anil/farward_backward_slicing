slicer.py  —  Smart Contract Program Slicer
============================================
Takes any Solidity contract as input. Finds all external calls,
runs backward + forward slice on each, intersects them, and reports
only REAL at-risk variables — no false positives.

Usage:
    python slicer.py <contract.sol> <ContractName>

Requires:
    npm install -g solc
    pip install slither-analyzer networkx
