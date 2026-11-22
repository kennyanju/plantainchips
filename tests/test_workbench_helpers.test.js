const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  calculateEntropy,
  redactText,
  parseIpv4,
  parseCidr,
  cidrContains,
  levenshtein,
  parseRqlToAst,
  escapeHtml,
  getActiveAppFindings,
  buildSarifReport,
  saveWorkbenchSession,
  loadWorkbenchSession,
  resetWorkbenchSession,
  APPS
} = require('../web/js/workbench.js');

test('calculateEntropy evaluates Shannon entropy correctly', () => {
  assert.equal(calculateEntropy(''), 0);
  assert.equal(calculateEntropy(null), 0);
  assert.equal(calculateEntropy('aaaaaaaa'), 0);
  assert.equal(calculateEntropy('01010101'), 1.0);

  const lowEntropy = calculateEntropy('abcabcabc');
  const highEntropy = calculateEntropy('xK9#vL2$pQ8@zM1!wR4&');
  assert.ok(highEntropy > lowEntropy);
  assert.ok(highEntropy > 3.0);
});

test('redactText masks PII, credit cards, and cloud access credentials', () => {
  // SSN masking
  const ssnInput = 'Customer SSN is 123-45-6789 in record.';
  const ssnRedacted = redactText(ssnInput);
  assert.ok(!ssnRedacted.includes('123-45-6789'));
  assert.ok(ssnRedacted.includes('123-**-****'));

  // Credit card masking
  const ccInput = 'Card number: 4111-2222-3333-4444 on file.';
  const ccRedacted = redactText(ccInput);
  assert.ok(!ccRedacted.includes('2222-3333'));
  assert.ok(ccRedacted.includes('4111-****-****-4444'));

  // AWS Access Key ID masking
  const awsInput = 'Found access key AKIAIOSFODNN7EXAMPLE in config.';
  const awsRedacted = redactText(awsInput);
  assert.ok(!awsRedacted.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(awsRedacted.includes('AKIAIOSF************'));

  // OpenAI / Stripe token masking
  const skInput = 'API key sk-1234567890abcdef1234567890 active.';
  const skRedacted = redactText(skInput);
  assert.ok(!skRedacted.includes('1234567890abcdef1234567890'));
  assert.ok(skRedacted.includes('sk-1234****************'));

  // Benign text remains unchanged
  const benign = 'Clean logging output with standard messages.';
  assert.equal(redactText(benign), benign);
});

test('parseIpv4 parses valid 32-bit addresses and rejects invalid formats', () => {
  assert.equal(parseIpv4('0.0.0.0'), 0);
  assert.equal(parseIpv4('255.255.255.255'), 4294967295);
  assert.equal(parseIpv4('192.168.1.1'), 3232235777);

  assert.equal(parseIpv4(''), null);
  assert.equal(parseIpv4('10.0.0'), null);
  assert.equal(parseIpv4('10.0.0.256'), null);
  assert.equal(parseIpv4('invalid.host.address.here'), null);
});

test('parseCidr and cidrContains calculate subnet containment accurately', () => {
  const cidr16 = parseCidr('10.0.0.0/16');
  assert.ok(cidr16 !== null);

  const ipInside = parseIpv4('10.0.50.25');
  const ipOutside = parseIpv4('10.1.0.1');

  assert.ok(cidrContains(cidr16, ipInside));
  assert.ok(!cidrContains(cidr16, ipOutside));

  // Default internet route /0 contains everything
  const cidrAll = parseCidr('0.0.0.0/0');
  assert.ok(cidrContains(cidrAll, parseIpv4('8.8.8.8')));
  assert.ok(cidrContains(cidrAll, parseIpv4('172.16.0.1')));

  // Single host IP without prefix parsed as /32
  const hostCidr = parseCidr('192.168.1.100');
  assert.ok(cidrContains(hostCidr, parseIpv4('192.168.1.100')));
  assert.ok(!cidrContains(hostCidr, parseIpv4('192.168.1.101')));

  // Invalid CIDR inputs
  assert.equal(parseCidr('invalid/format'), null);
  assert.equal(parseCidr('10.0.0.0/35'), null);
});

test('levenshtein computes editing distance for typosquat detection', () => {
  assert.equal(levenshtein('react', 'react'), 0);
  assert.equal(levenshtein('requests', 'requsts'), 1);
  assert.equal(levenshtein('lodash', '1odash'), 1);
  assert.equal(levenshtein('express', 'express-auth'), 5);
  assert.equal(levenshtein('', 'flask'), 5);
  assert.equal(levenshtein('django', ''), 6);
});

test('parseRqlToAst compiles RQL statements into structured AST objects', () => {
  const query = "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = restrictPublicBuckets is false limit 25";
  const ast = parseRqlToAst(query);

  assert.equal(ast.status, 'VALID');
  assert.equal(ast.family, 'config');
  assert.equal(ast.target, 'cloud.resource');
  assert.equal(ast.limit, 25);
  assert.equal(ast.predicates.length, 3);

  const p1 = ast.predicates[0];
  assert.equal(p1.field, 'cloud.type');
  assert.equal(p1.op, '==');
  assert.equal(p1.value, 'aws');

  const p3 = ast.predicates[2];
  assert.equal(p3.field, 'restrictPublicBuckets');
  assert.equal(p3.op, 'is_false');
  assert.equal(p3.value, false);

  // Empty query error
  const emptyRes = parseRqlToAst('');
  assert.equal(emptyRes.status, 'ERROR');

  // Syntax error
  const syntaxErr = parseRqlToAst('select * from tables');
  assert.equal(syntaxErr.status, 'SYNTAX_ERROR');
});

test('escapeHtml safely sanitizes HTML special characters', () => {
  const raw = '<script>alert("xss" & \'hack\')</script>';
  const escaped = escapeHtml(raw);

  assert.ok(!escaped.includes('<script>'));
  assert.ok(escaped.includes('&lt;script&gt;'));
  assert.ok(escaped.includes('&quot;xss&quot;'));
  assert.ok(escaped.includes('&#039;hack&#039;'));
  assert.ok(escaped.includes('&amp;'));
});

test('parseRqlToAst rejects invalid families, unterminated quotes, and preserves escaped quotes', () => {
  assert.equal(parseRqlToAst('hello world').status, 'SYNTAX_ERROR');
  assert.equal(parseRqlToAst('unknown from cloud.resource where x = 1').status, 'SYNTAX_ERROR');
  assert.equal(parseRqlToAst("config from cloud.resource where region = 'us-east-1").status, 'SYNTAX_ERROR');
  assert.equal(parseRqlToAst('config from cloud.resource where ').status, 'SYNTAX_ERROR');

  const escapedAst = parseRqlToAst("config from cloud.resource where description contains 'it\\'s and more' limit 10");
  assert.equal(escapedAst.status, 'VALID');
  assert.equal(escapedAst.limit, 10);
  assert.equal(escapedAst.predicates.length, 1);
  assert.equal(escapedAst.predicates[0].value, "it's and more");
});

test('getActiveAppFindings resolves real telemetry across all 14 apps without placeholders', () => {
  const appIds = Object.keys(APPS);
  assert.equal(appIds.length, 14);
  for (const appId of appIds) {
    const findings = getActiveAppFindings(appId);
    assert.ok(Array.isArray(findings));
    for (const f of findings) {
      assert.ok(!f.id.startsWith(`SEC-${appId.toUpperCase()}-001`), `Placeholder finding returned for ${appId}`);
    }
  }
});

test('buildSarifReport deduplicates driver rules by ruleId', () => {
  const app = APPS.posturesecure;
  const dupFindings = [
    { id: 'DUP-RULE-01', severity: 'CRITICAL', resource: 'res-a', description: 'First instance', remediation: 'Fix A' },
    { id: 'DUP-RULE-01', severity: 'HIGH', resource: 'res-b', description: 'Second instance', remediation: 'Fix B' },
    { id: 'UNIQUE-RULE-02', severity: 'MEDIUM', resource: 'res-c', description: 'Third instance' }
  ];
  const sarif = buildSarifReport(app, dupFindings);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 3);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2);
  assert.deepEqual(sarif.runs[0].tool.driver.rules.map(r => r.id), ['DUP-RULE-01', 'UNIQUE-RULE-02']);
});

test('workbench session persists to and resets from localStorage', () => {
  const storeMap = new Map();
  const prevStorage = globalThis.localStorage;
  globalThis.localStorage = {
    getItem: (k) => (storeMap.has(k) ? storeMap.get(k) : null),
    setItem: (k, v) => storeMap.set(k, String(v)),
    removeItem: (k) => storeMap.delete(k)
  };
  try {
    saveWorkbenchSession();
    assert.ok(storeMap.has('cloudsecure.workbench.v1'));
    loadWorkbenchSession();
    resetWorkbenchSession();
    assert.ok(!storeMap.has('cloudsecure.workbench.v1'));
  } finally {
    globalThis.localStorage = prevStorage;
  }
});
