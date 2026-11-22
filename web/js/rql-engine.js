// CloudSecure Shared Client-Side RQL Parser & Evaluator
// Used by rql.html, index.html (app.js), PolicySecure (workbench.js), and Node tests.

(function(globalScope) {
  'use strict';

  const VALID_FAMILIES = new Set(['config', 'iam', 'event', 'data', 'network', 'ai']);

  function splitTopLevelLogical(clause) {
    const parts = [];
    let depth = 0;
    let quoteChar = null;
    let start = 0;
    const len = clause.length;

    let i = 0;
    while (i < len) {
      const ch = clause[i];
      if (quoteChar) {
        if (ch === '\\' && i + 1 < len) {
          i += 2;
          continue;
        }
        if (ch === quoteChar) {
          quoteChar = null;
        }
      } else if (ch === '\'' || ch === '"') {
        quoteChar = ch;
      } else if (ch === '(') {
        depth++;
      } else if (ch === ')' && depth > 0) {
        depth--;
      } else if (depth === 0) {
        const rest = clause.slice(i);
        const match = rest.match(/^\s+(?:and|or)\s+/i);
        if (match) {
          parts.push(clause.slice(start, i).trim());
          start = i + match[0].length;
          i = start;
          continue;
        }
      }
      i++;
    }

    if (start < len) {
      parts.push(clause.slice(start).trim());
    }
    return parts.filter(Boolean);
  }

  function stripQuotes(val) {
    const trimmed = (val || '').trim();
    if ((trimmed.startsWith('\'') && trimmed.endsWith('\'')) ||
        (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
      return trimmed.slice(1, -1).replace(/\\(['"\\])/g, '$1');
    }
    return trimmed;
  }

  function hasBalancedQuotes(str) {
    let quoteChar = null;
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (quoteChar) {
        if (ch === '\\' && i + 1 < str.length) {
          i++;
          continue;
        }
        if (ch === quoteChar) {
          quoteChar = null;
        }
      } else if (ch === '\'' || ch === '"') {
        quoteChar = ch;
      }
    }
    return quoteChar === null;
  }

  function parseRqlToAst(query) {
    const raw = (query || '').trim();
    if (!raw) {
      return { status: 'ERROR', error: 'Empty RQL query. Enter a statement such as: config from cloud.resource where ...' };
    }

    if (!hasBalancedQuotes(raw)) {
      return {
        rawQuery: raw,
        status: 'SYNTAX_ERROR',
        error: 'RQL Parse Error: Unterminated string literal in query.'
      };
    }

    const m = raw.match(/^([a-zA-Z]+)\s+from\s+([a-zA-Z0-9_.\-]+)(?:\s+where\s+(.*?))?(?:\s+limit\s+(\d+))?$/i);
    if (!m) {
      return {
        rawQuery: raw,
        status: 'SYNTAX_ERROR',
        error: 'Invalid RQL syntax. Expected: <family> from <target> [where <predicates>] [limit <n>].'
      };
    }

    const family = m[1].toLowerCase();
    if (!VALID_FAMILIES.has(family)) {
      return {
        rawQuery: raw,
        status: 'SYNTAX_ERROR',
        error: `RQL Parse Error: Unknown resource family '${m[1]}'. Expected one of: config, iam, event, data, network, ai.`
      };
    }

    const target = m[2];
    const whereClause = m[3] ? m[3].trim() : '';
    const limit = m[4] ? parseInt(m[4], 10) : null;

    if (/\s+where\s*$/i.test(raw)) {
      return {
        rawQuery: raw,
        status: 'SYNTAX_ERROR',
        error: 'RQL Parse Error: Trailing WHERE keyword without filter predicates.'
      };
    }

    const predicates = [];
    if (whereClause) {
      const parts = splitTopLevelLogical(whereClause);
      for (let part of parts) {
        let p = part.trim();
        if (!p) continue;
        while (p.startsWith('(') && p.endsWith(')')) {
          p = p.slice(1, -1).trim();
        }

        let op = '==';
        let field = '';
        let val = null;

        if (/\bis\s+false\b/i.test(p)) {
          field = p.replace(/\s+is\s+false/i, '').trim();
          op = 'is_false';
          val = false;
        } else if (/\bis\s+true\b/i.test(p)) {
          field = p.replace(/\s+is\s+true/i, '').trim();
          op = 'is_true';
          val = true;
        } else if (/\bis\s+empty\b/i.test(p)) {
          field = p.replace(/\s+is\s+empty/i, '').trim();
          op = 'is_empty';
          val = true;
        } else if (/\bis\s+not\s+empty\b/i.test(p)) {
          field = p.replace(/\s+is\s+not\s+empty/i, '').trim();
          op = 'is_not_empty';
          val = true;
        } else if (/\bnot\s+in\b/i.test(p)) {
          const s = p.split(/\s+not\s+in\s+/i);
          field = s[0].trim();
          val = s[1].trim().replace(/^[\(\[]|[\)\]]$/g, '').split(',').map(stripQuotes);
          op = 'not_in';
        } else if (/\bin\b/i.test(p)) {
          const s = p.split(/\s+in\s+/i);
          field = s[0].trim();
          val = s[1].trim().replace(/^[\(\[]|[\)\]]$/g, '').split(',').map(stripQuotes);
          op = 'in';
        } else if (/\bcontains\b/i.test(p)) {
          const s = p.split(/\s+contains\s+/i);
          field = s[0].trim();
          val = stripQuotes(s[1]);
          op = 'contains';
        } else if (/\bstarts\s+with\b/i.test(p)) {
          const s = p.split(/\s+starts\s+with\s+/i);
          field = s[0].trim();
          val = stripQuotes(s[1]);
          op = 'starts_with';
        } else if (p.includes('!=')) {
          const idx = p.indexOf('!=');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 2));
          op = '!=';
        } else if (p.includes('>=')) {
          const idx = p.indexOf('>=');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 2));
          op = '>=';
        } else if (p.includes('<=')) {
          const idx = p.indexOf('<=');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 2));
          op = '<=';
        } else if (p.includes('>')) {
          const idx = p.indexOf('>');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 1));
          op = '>';
        } else if (p.includes('<')) {
          const idx = p.indexOf('<');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 1));
          op = '<';
        } else if (p.includes('==')) {
          const idx = p.indexOf('==');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 2));
          op = '==';
        } else if (p.includes('=')) {
          const idx = p.indexOf('=');
          field = p.slice(0, idx).trim();
          val = stripQuotes(p.slice(idx + 1));
          op = '==';
        } else {
          return {
            rawQuery: raw,
            status: 'SYNTAX_ERROR',
            error: `RQL Parse Error: Unrecognized predicate expression '${p}'. Expected comparison operator (=, ==, !=, >, <, in, contains, is true/false).`
          };
        }

        if (/^json\.rule\s*=\s*/i.test(field)) {
          field = field.replace(/^json\.rule\s*=\s*/i, '').trim();
        }

        if (!field) {
          return {
            rawQuery: raw,
            status: 'SYNTAX_ERROR',
            error: `RQL Parse Error: Missing attribute name in predicate '${p}'.`
          };
        }

        predicates.push({ field, op, value: val });
      }
    }

    return {
      family,
      target,
      predicates,
      limit,
      rawQuery: raw,
      status: 'VALID',
      compiler: 'Zero-Copy RQL AST Engine (Compiled)',
      compiledAt: new Date().toISOString()
    };
  }

  const RqlEngine = {
    parseRqlToAst,
    VALID_FAMILIES
  };

  if (typeof globalScope !== 'undefined' && globalScope) {
    globalScope.CloudSecureRql = RqlEngine;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = RqlEngine;
  }
})(typeof window !== 'undefined' ? window : globalThis);
