class BaseDetector {
  constructor(name, description, severity) {
    this.name = name;
    this.description = description;
    this.severity = severity;
    this.findings = [];
  }

  async detect(ast, sourceCode, fileName) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');

    // Traverse the AST
    this.traverse(ast);

    return this.findings;
  }

  traverse(node) {
    if (!node) return;

    // Visit the node
    const methodName = `visit${node.type}`;
    if (typeof this[methodName] === 'function') {
      this[methodName](node);
    }

    // Traverse children
    for (const key in node) {
      if (key === 'loc' || key === 'range') continue;

      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => this.traverse(c));
      } else if (child && typeof child === 'object' && child.type) {
        this.traverse(child);
      }
    }
  }

  addFinding(vulnerability) {
    this.findings.push({
      detector: this.name,
      severity: vulnerability.severity || this.severity,
      confidence: vulnerability.confidence || 'MEDIUM', // HIGH, MEDIUM, LOW
      title: vulnerability.title,
      description: vulnerability.description,
      location: vulnerability.location,
      fileName: this.fileName,
      line: vulnerability.line,
      column: vulnerability.column,
      code: vulnerability.code,
      recommendation: vulnerability.recommendation,
      references: vulnerability.references || []
    });
  }

  getCodeSnippet(loc) {
    if (!loc || !loc.start) return '';

    const startLine = loc.start.line - 1;
    const endLine = loc.end ? loc.end.line - 1 : startLine;

    return this.sourceLines.slice(
      Math.max(0, startLine),
      Math.min(this.sourceLines.length, endLine + 1)
    ).join('\n');
  }

  getLineContent(lineNumber) {
    if (lineNumber < 1 || lineNumber > this.sourceLines.length) return '';
    return this.sourceLines[lineNumber - 1];
  }
}

module.exports = BaseDetector;
