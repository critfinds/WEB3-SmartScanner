# WEB3CRIT-Scanner Quick Start Guide

## Installation

The scanner is ready to use! Dependencies are already installed.

## Quick Test

Test the scanner with the example vulnerable contract:

```bash
cd tools/Web3CRIT-Scanner
node src/cli.js scan examples/VulnerableContract.sol
```

## Basic Usage

### Scan a single contract:
```bash
node src/cli.js scan path/to/YourContract.sol
```

### Scan all contracts in a directory:
```bash
node src/cli.js scan path/to/contracts/
```

### Filter by severity (only show critical/high):
```bash
node src/cli.js scan contracts/ --severity high
```

### Save report:
```bash
# Markdown format
node src/cli.js scan contracts/ --output report.md --format markdown

# JSON format
node src/cli.js scan contracts/ --output report.json --format json
```

### Verbose mode:
```bash
node src/cli.js scan contracts/ --verbose
```

## What Gets Detected

The scanner detects 10 critical vulnerability types:

1. **Reentrancy** - Classic and cross-function reentrancy attacks
2. **Access Control** - Missing or improper access modifiers
3. **Unchecked Calls** - External calls without return value checks
4. **Delegatecall** - Dangerous delegatecall usage
5. **Front-Running** - Transaction ordering vulnerabilities
6. **Timestamp Issues** - Dangerous reliance on block.timestamp
7. **Logic Bugs** - Common programming errors
8. **Selfdestruct** - Unprotected contract destruction
9. **Price Manipulation** - Oracle and price feed vulnerabilities
10. **Integer Overflow** - Unchecked arithmetic (Solidity < 0.8)

## Example Output

The scanner found **34 vulnerabilities** in the example contract including:

- 17 Critical issues
- 16 High severity issues
- 1 Medium severity issue

Each finding includes:
- Vulnerability title and severity
- Exact location (file:line:column)
- Code snippet showing the issue
- Detailed explanation
- Remediation recommendation
- Reference links for more information

## Integration with Your Workflow

### Pre-commit Hook
Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
node tools/Web3CRIT-Scanner/src/cli.js scan contracts/ --severity critical
exit $?
```

### Before Deployment Checklist
```bash
# Run full scan
node src/cli.js scan contracts/ --output audit-report.md

# Review all critical and high findings
node src/cli.js scan contracts/ --severity high

# Generate JSON for automated processing
node src/cli.js scan contracts/ --format json > findings.json
```

## Programmatic Usage

```javascript
const Web3CRITScanner = require('./src/scanner');

const scanner = new Web3CRITScanner({ severity: 'high' });
await scanner.scanFile('./contracts/MyContract.sol');

const { findings, stats } = scanner.getFindings();
console.log(`Found ${stats.critical} critical issues`);
```

## Getting Help

```bash
# View all commands
node src/cli.js --help

# View detector information
node src/cli.js info

# Command help
node src/cli.js scan --help
```

## Next Steps

1. Scan your contracts: `node src/cli.js scan your-contracts/`
2. Review findings and fix critical/high issues
3. Generate audit report for documentation
4. Integrate into CI/CD pipeline
5. Combine with other tools (Slither, Mythril) for comprehensive coverage

## Important Notes

- This is a **static analysis tool** - it complements but doesn't replace manual audits
- **Review all findings** - some may be false positives depending on your code
- **Critical/High findings** should be addressed before deployment
- Use alongside professional security audits for high-value contracts

## Support

For issues or questions:
- Check README.md for detailed documentation
- Review example vulnerable contract in examples/
- Examine detector source code in src/detectors/
