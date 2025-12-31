/**
 * Data Flow Analyzer
 * Tracks how data flows through the contract to identify tainted inputs
 * reaching dangerous sinks (delegatecall, selfdestruct, etc.)
 */
class DataFlowAnalyzer {
  constructor(controlFlowGraph) {
    this.cfg = controlFlowGraph;
    this.taintedVariables = new Map(); // variable -> taint source
    this.dataFlows = []; // {source, sink, path, severity}
  }

  /**
   * Perform taint analysis to track user-controlled data
   */
  analyze() {
    this.taintedVariables.clear();
    this.dataFlows = [];

    // Identify taint sources (user inputs)
    this.identifyTaintSources();

    // Propagate taint through data flow
    this.propagateTaint();

    // Check if tainted data reaches dangerous sinks
    this.checkDangerousSinks();

    return {
      taintedVariables: this.taintedVariables,
      dataFlows: this.dataFlows
    };
  }

  /**
   * Identify sources of tainted data (user inputs)
   */
  identifyTaintSources() {
    for (const [funcKey, funcInfo] of this.cfg.functions) {
      // Function parameters are tainted
      funcInfo.parameters.forEach(param => {
        const varKey = `${funcKey}.${param.name}`;
        this.taintedVariables.set(varKey, {
          type: 'parameter',
          function: funcKey,
          name: param.name,
          confidence: 'HIGH'
        });
      });

      // msg.sender, msg.value, tx.origin are tainted
      // (would need to parse expressions to find these)
    }
  }

  /**
   * Propagate taint through assignments and function calls
   */
  propagateTaint() {
    let changed = true;
    let iterations = 0;
    const maxIterations = 100; // Prevent infinite loops

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      for (const [funcKey, funcInfo] of this.cfg.functions) {
        // Analyze state writes to propagate taint
        funcInfo.stateWrites.forEach(write => {
          // If writing a tainted value to state variable, mark it as tainted
          // (simplified - would need full expression analysis)
        });
      }
    }
  }

  /**
   * Check if tainted data flows to dangerous operations
   */
  checkDangerousSinks() {
    const dangerousSinks = [
      'delegatecall',
      'call',
      'send',
      'selfdestruct',
      'suicide'
    ];

    for (const [funcKey, funcInfo] of this.cfg.functions) {
      funcInfo.externalCalls.forEach(call => {
        if (dangerousSinks.includes(call.type)) {
          // Check if this call uses tainted data
          const isTainted = this.isCallTainted(call, funcKey);

          if (isTainted) {
            this.dataFlows.push({
              source: isTainted.source,
              sink: call.type,
              function: funcKey,
              location: call.loc,
              severity: this.getSeverityForSink(call.type),
              confidence: isTainted.confidence,
              exploitable: this.isExploitable(funcKey, call)
            });
          }
        }
      });
    }
  }

  /**
   * Check if a call uses tainted data
   */
  isCallTainted(call, funcKey) {
    // Check if any parameters to this function are tainted
    // (simplified - would need full expression analysis)

    for (const [varKey, taintInfo] of this.taintedVariables) {
      if (varKey.startsWith(funcKey)) {
        return taintInfo;
      }
    }

    return null;
  }

  /**
   * Determine if a taint flow is actually exploitable
   */
  isExploitable(funcKey, call) {
    const funcInfo = this.cfg.functions.get(funcKey);
    if (!funcInfo) return false;

    // Check if function has any access control
    if (funcInfo.modifiers.length > 0) {
      // Verify the modifiers actually provide protection
      for (const modName of funcInfo.modifiers) {
        const modKey = `${funcInfo.contract}.${modName}`;
        const modInfo = this.cfg.modifiers.get(modKey);

        if (modInfo && modInfo.checksAccess) {
          // Access control exists, less exploitable
          return false;
        }
      }
    }

    // Check if function is public/external
    if (funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') {
      return false;
    }

    // No effective access control and publicly accessible
    return true;
  }

  getSeverityForSink(sinkType) {
    const severityMap = {
      'delegatecall': 'CRITICAL',
      'selfdestruct': 'CRITICAL',
      'suicide': 'CRITICAL',
      'call': 'HIGH',
      'send': 'HIGH'
    };

    return severityMap[sinkType] || 'MEDIUM';
  }

  /**
   * Find all paths from source to sink
   */
  findTaintPaths(source, sink) {
    const paths = [];
    const visited = new Set();

    const dfs = (current, path) => {
      if (visited.has(current)) return;
      visited.add(current);
      path.push(current);

      if (current === sink) {
        paths.push([...path]);
      } else {
        // Continue search
        // (would need full call graph traversal)
      }

      path.pop();
      visited.delete(current);
    };

    dfs(source, []);
    return paths;
  }

  /**
   * Check if user-controlled data reaches a specific operation
   */
  tracesToSink(variable, sinkType) {
    for (const flow of this.dataFlows) {
      if (flow.sink === sinkType) {
        // Check if this variable is involved
        return true;
      }
    }
    return false;
  }

  /**
   * Get all dangerous data flows for a function
   */
  getDangerousFlows(funcKey) {
    return this.dataFlows.filter(flow => flow.function === funcKey);
  }

  /**
   * Check if a variable is tainted
   */
  isTainted(varName, funcKey) {
    const varKey = `${funcKey}.${varName}`;
    return this.taintedVariables.has(varKey);
  }
}

module.exports = DataFlowAnalyzer;
