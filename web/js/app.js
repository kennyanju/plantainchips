document.addEventListener('DOMContentLoaded', () => {
  // 1. App Filtering & Search
  const filterPills = document.querySelectorAll('.filter-pill');
  const appCards = document.querySelectorAll('.app-card-item');
  const searchInput = document.getElementById('app-search-input');
  const appCountLabel = document.getElementById('app-count-label');

  let activeCategory = 'all';
  let searchQuery = '';

  function filterApps() {
    let visibleCount = 0;
    appCards.forEach(card => {
      const category = card.getAttribute('data-category') || '';
      const textContent = card.textContent.toLowerCase();
      const matchesCategory = activeCategory === 'all' || category === activeCategory;
      const matchesSearch = !searchQuery || textContent.includes(searchQuery);

      if (matchesCategory && matchesSearch) {
        card.style.display = 'flex';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    if (appCountLabel) {
      appCountLabel.textContent = `Showing ${visibleCount} of ${appCards.length} applications`;
    }

    const emptyBox = document.getElementById('app-filter-empty');
    if (emptyBox) {
      emptyBox.style.display = visibleCount === 0 ? 'flex' : 'none';
    }
  }

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeCategory = pill.getAttribute('data-filter') || 'all';
      filterApps();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      filterApps();
    });
  }

  // 2. Interactive RQL Playground
  const rqlInput = document.getElementById('rql-editor-input');
  const rqlRunBtn = document.getElementById('rql-run-btn');
  const rqlOutput = document.getElementById('rql-output-container');
  const rqlStatus = document.getElementById('rql-status-text');
  const rqlPresetBtns = document.querySelectorAll('.rql-preset-btn');

  const rqlPresets = {
    s3_public: {
      query: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = publicAccessBlockConfiguration.restrictPublicBuckets is false",
      target: "PostureSecure (CSPM)",
      time: "24 ms",
      findings: [
        { id: "SEC-AWS-S3-042", res: "arn:aws:s3:::prod-customer-exports", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "S3 bucket has RestrictPublicBuckets set to false. Object ACLs permit public read." },
        { id: "SEC-AWS-S3-042", res: "arn:aws:s3:::marketing-static-assets", sev: "HIGH", glyph: "[/!\\]", badge: "badge-high", desc: "Bucket lacks bucket policy forcing TLS 1.2+." }
      ]
    },
    iam_admin: {
      query: "iam from cloud.entitlements where source.type = 'role' and dest.action contains 'iam:*' and dest.resource = '*'",
      target: "IdentitySecure (CIEM)",
      time: "18 ms",
      findings: [
        { id: "SEC-IAM-019", res: "arn:aws:iam::123456789012:role/DeployerServiceRole", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "Full iam:* wildcard permissions attached without permission boundary." },
        { id: "SEC-IAM-033", res: "arn:aws:iam::123456789012:role/LegacyCiRunner", sev: "HIGH", glyph: "[/!\\]", badge: "badge-high", desc: "AssumeRole policy permits sts:AssumeRole from wildcard principal." }
      ]
    },
    container_root: {
      query: "event from cloud.workload where runtime.syscall in ('execve', 'ptrace') and container.user.uid == 0",
      target: "WorkloadSecure (CWPP)",
      time: "32 ms",
      findings: [
        { id: "SEC-CWPP-104", res: "k8s://prod-cluster/ns/payments/pod/gateway-7d8b9-x4r", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "Interactive root shell spawned inside payment container via execve /bin/bash." }
      ]
    },
    pii_leak: {
      query: "data from cloud.data_store where data.classification in ('PII', 'PCI') and storage.is_public == true",
      target: "DataSecure (DSPM)",
      time: "41 ms",
      findings: [
        { id: "SEC-DSPM-008", res: "snowflake://account/analytics_db/raw_customers", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "Table contains 14,200 unmasked social security numbers exposed to public share." }
      ]
    },
    ai_jailbreak: {
      query: "ai from cloud.model where prompt.injection.detected == true and model.guardrail == 'disabled'",
      target: "AiSecure (AI Guardian)",
      time: "15 ms",
      findings: [
        { id: "SEC-AI-LLM01", res: "bedrock://model/anthropic.claude-3-haiku", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "Adversarial jailbreak payload detected attempting prompt extraction and model system bypass." }
      ]
    },
    net_cross_zone: {
      query: "network from cloud.vpc where source.tier == 'frontend' and dest.tier == 'database' and firewall.action == 'allow'",
      target: "NetSecure (Zero Trust)",
      time: "21 ms",
      findings: [
        { id: "SEC-NET-SEG04", res: "vpc-peering://prod-vpc-peer-904", sev: "HIGH", glyph: "[/!\\]", badge: "badge-high", desc: "Direct perimeter ingress route to internal production database subnet violates tier microsegmentation." }
      ]
    },
    threat_c2: {
      query: "event from cloud.network where connection.state == 'established' and dest.ip in c2_threat_intel and egress.bytes > 10000000",
      target: "ThreatSecure (CDR)",
      time: "28 ms",
      findings: [
        { id: "SEC-CDR-ACT09", res: "eni://prod-bastion-public-iface", sev: "CRITICAL", glyph: "[!]", badge: "badge-crit", desc: "High-volume egress connection established to known adversary C2 infrastructure. Automated quarantine engaged." }
      ]
    },
    supply_unsigned: {
      query: "event from cloud.build where artifact.digest != null and sigstore.signature == null",
      target: "SupplySecure (SSCS)",
      time: "19 ms",
      findings: [
        { id: "SEC-SSCS-SIG01", res: "registry://docker.io/acme/payment-worker:v2.1", sev: "HIGH", glyph: "[/!\\]", badge: "badge-high", desc: "Production container deployed without Cosign cryptographic signature or Rekor transparency proof." }
      ]
    },
    empty_example: {
      query: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'compute.firewalls' and json.rule = allowed[].ports contains '22' and sourceRanges contains '0.0.0.0/0'",
      target: "PostureSecure (CSPM)",
      time: "12 ms",
      findings: []
    },
    error_example: {
      query: "syntax error from unknown.cloud where invalid token %%%",
      target: "PolicySecure (RQL Studio)",
      time: "3 ms",
      error: "RQL Parse Error at line 1, column 25: Expected resource family identifier (config, event, network, iam, data, ai). Got invalid token '%%%'. Check RQL grammar specification."
    }
  };

  rqlPresetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.getAttribute('data-preset');
      if (rqlPresets[key]) {
        rqlInput.value = rqlPresets[key].query;
        executeRql(rqlPresets[key]);
      }
    });
  });

  function escapeHtmlText(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function executeRql(presetData) {
    if (!rqlOutput) return;

    // Show loading state first (R-27)
    rqlOutput.innerHTML = `
      <div class="state-box">
        <div class="hud-label" style="color: var(--accent-ink);">EXECUTING QUERY PLAN...</div>
        <p class="state-desc">Compiling AST, filtering columnar graph predicates across multi-cloud inventory...</p>
      </div>
    `;
    if (rqlStatus) {
      rqlStatus.textContent = "Status: Evaluating...";
    }

    setTimeout(() => {
      if (presetData.error) {
        // Error state (R-27)
        rqlOutput.innerHTML = `
          <div class="state-box state-error">
            <div class="state-title">[!] QUERY EXECUTION FAILED</div>
            <p class="state-desc">${escapeHtmlText(presetData.error)}</p>
            <button class="btn btn-secondary btn-sm" id="rql-edit-focus-btn" type="button">Edit Query</button>
          </div>
        `;
        if (rqlStatus) {
          rqlStatus.textContent = `Status: Error in ${presetData.time}`;
        }
        return;
      }

      if (!presetData.findings || presetData.findings.length === 0) {
        // Empty state (R-27)
        rqlOutput.innerHTML = `
          <div class="state-box">
            <div class="badge-sev badge-pass">[OK] ZERO VIOLATIONS</div>
            <div class="state-title">Clean Assessment</div>
            <p class="state-desc">All evaluated cloud assets adhere strictly to this policy rule. No misconfigurations or toxic combinations detected.</p>
          </div>
        `;
        if (rqlStatus) {
          rqlStatus.textContent = `Status: 0 findings (${presetData.time}) - Target: ${presetData.target}`;
        }
        return;
      }

      // Findings Table
      let rows = presetData.findings.map(f => `
        <tr>
          <td><span class="badge-sev ${f.badge}">${f.glyph} ${f.sev}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600;">${escapeHtmlText(f.id)}</td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtmlText(f.res)}</td>
          <td>${escapeHtmlText(f.desc)}</td>
          <td>
            <button class="btn btn-secondary btn-sm copy-btn" type="button" data-copy="${escapeHtmlText(`terraform fix: ${f.id} on ${f.res}`)}">
              Remediation
            </button>
          </td>
        </tr>
      `).join('');

      rqlOutput.innerHTML = `
        <table class="hud-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Resource Target</th>
              <th>Diagnostic Description</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      `;

      if (rqlStatus) {
        rqlStatus.textContent = `Status: ${presetData.findings.length} findings (${presetData.time}) - Target: ${presetData.target}`;
      }
    }, 200);
  }

  function evaluateCustomRql(rawQuery) {
    const parser = window.CloudSecureRql && window.CloudSecureRql.parseRqlToAst;
    if (!parser) {
      return rqlPresets.s3_public;
    }

    const ast = parser(rawQuery);
    if (ast.status !== 'VALID') {
      return {
        query: rawQuery,
        target: 'PolicySecure (RQL Parser)',
        time: '2 ms',
        error: ast.error || 'Invalid RQL query syntax.'
      };
    }

    const q = rawQuery.toLowerCase();
    const applyLimit = (preset) => {
      if (ast.limit && ast.limit > 0 && Array.isArray(preset.findings)) {
        return Object.assign({}, preset, { findings: preset.findings.slice(0, ast.limit) });
      }
      return preset;
    };

    if (ast.family === 'config') {
      if (q.includes('gcp') || q.includes('compute.firewalls')) {
        return applyLimit(rqlPresets.empty_example);
      }
      if (q.includes('aws-s3-bucket') || q.includes('restrictpublicbuckets') || q.includes('s3')) {
        return applyLimit(rqlPresets.s3_public);
      }
    } else if (ast.family === 'iam') {
      if (q.includes('role') || q.includes('iam:*') || q.includes('entitlements') || ast.predicates.length === 0) {
        return applyLimit(rqlPresets.iam_admin);
      }
    } else if (ast.family === 'event') {
      if (q.includes('sigstore') || q.includes('signature') || q.includes('artifact') || q.includes('build')) {
        return applyLimit(rqlPresets.supply_unsigned);
      }
      if (q.includes('c2') || q.includes('egress') || q.includes('network')) {
        return applyLimit(rqlPresets.threat_c2);
      }
      if (q.includes('workload') || q.includes('execve') || q.includes('uid') || ast.predicates.length === 0) {
        return applyLimit(rqlPresets.container_root);
      }
    } else if (ast.family === 'data') {
      if (q.includes('pii') || q.includes('pci') || q.includes('is_public') || ast.predicates.length === 0) {
        return applyLimit(rqlPresets.pii_leak);
      }
    } else if (ast.family === 'ai') {
      if (q.includes('prompt') || q.includes('jailbreak') || q.includes('guardrail') || ast.predicates.length === 0) {
        return applyLimit(rqlPresets.ai_jailbreak);
      }
    } else if (ast.family === 'network') {
      if (q.includes('vpc') || q.includes('tier') || q.includes('firewall') || ast.predicates.length === 0) {
        return applyLimit(rqlPresets.net_cross_zone);
      }
    }

    const familyLabels = {
      config: 'PostureSecure (CSPM)',
      iam: 'IdentitySecure (CIEM)',
      event: 'WorkloadSecure & ThreatSecure',
      data: 'DataSecure (DSPM)',
      network: 'NetSecure (CNS)',
      ai: 'AiSecure (AI-SPM)'
    };

    return {
      query: rawQuery,
      target: `${familyLabels[ast.family] || 'CloudSecure Engine'} [${ast.target}]`,
      time: '14 ms',
      findings: []
    };
  }

  if (rqlRunBtn && rqlInput) {
    rqlRunBtn.addEventListener('click', () => {
      executeRql(evaluateCustomRql(rqlInput.value));
    });
  }

  // 3. Accessible Clipboard Copy with Fallback (Single Delegated Listener)
  function copyTextFallback(text) {
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.top = '0';
      textarea.style.left = '0';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(textarea);
      return ok;
    } catch (e) {
      return false;
    }
  }

  function showCopiedFeedback(btn) {
    const originalText = btn.textContent;
    btn.textContent = 'COPIED!';
    btn.style.borderColor = 'var(--accent-ink)';
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.borderColor = '';
    }, 1800);
  }

  document.addEventListener('click', (e) => {
    const focusBtn = e.target.closest('#rql-edit-focus-btn');
    if (focusBtn && rqlInput) {
      rqlInput.focus();
      return;
    }

    const copyBtn = e.target.closest('.copy-btn');
    if (!copyBtn) return;

    const text = copyBtn.getAttribute('data-copy');
    if (!text) return;

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showCopiedFeedback(copyBtn);
      }).catch(() => {
        if (copyTextFallback(text)) {
          showCopiedFeedback(copyBtn);
        }
      });
    } else if (copyTextFallback(text)) {
      showCopiedFeedback(copyBtn);
    }
  });
});
