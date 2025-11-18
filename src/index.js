const Web3CRITScanner = require('./scanner');

// Export main scanner class
module.exports = Web3CRITScanner;

// Export individual detectors for advanced usage
module.exports.detectors = {
  ReentrancyDetector: require('./detectors/reentrancy'),
  IntegerOverflowDetector: require('./detectors/integer-overflow'),
  AccessControlDetector: require('./detectors/access-control'),
  UncheckedCallDetector: require('./detectors/unchecked-call'),
  DelegateCallDetector: require('./detectors/delegatecall'),
  FrontRunningDetector: require('./detectors/frontrunning'),
  TimestampDependenceDetector: require('./detectors/timestamp'),
  LogicBugDetector: require('./detectors/logic-bugs'),
  UnprotectedSelfdestructDetector: require('./detectors/selfdestruct'),
  PriceFeedManipulationDetector: require('./detectors/price-feed'),
  BaseDetector: require('./detectors/base-detector')
};

// Convenience function for quick scanning
module.exports.scan = async function(pathOrSource, options = {}) {
  const scanner = new Web3CRITScanner(options);

  try {
    const stats = require('fs').statSync(pathOrSource);

    if (stats.isDirectory()) {
      await scanner.scanDirectory(pathOrSource);
    } else if (stats.isFile()) {
      await scanner.scanFile(pathOrSource);
    }
  } catch (err) {
    // Assume it's source code if not a valid path
    await scanner.scanSource(pathOrSource);
  }

  return scanner.getFindings();
};

// Export version
module.exports.version = require('./package.json').version;
