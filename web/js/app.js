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
            <p class="state-desc">${presetData.error}</p>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('rql-editor-input').focus();">Edit Query</button>
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
          <td style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600;">${f.id}</td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${f.res}</td>
          <td>${f.desc}</td>
          <td>
            <button class="btn btn-secondary btn-sm copy-btn" data-copy="terraform fix: ${f.id} on ${f.res}">
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

      bindCopyButtons();
    }, 200);
  }

  if (rqlRunBtn && rqlInput) {
    rqlRunBtn.addEventListener('click', () => {
      const q = rqlInput.value.toLowerCase();
      if (q.includes('error') || q.includes('%%%')) {
        executeRql(rqlPresets.error_example);
      } else if (q.includes('firewall') || q.includes('gcp')) {
        executeRql(rqlPresets.empty_example);
      } else if (q.includes('iam') || q.includes('role')) {
        executeRql(rqlPresets.iam_admin);
      } else if (q.includes('workload') || q.includes('execve')) {
        executeRql(rqlPresets.container_root);
      } else if (q.includes('data') || q.includes('pii')) {
        executeRql(rqlPresets.pii_leak);
      } else {
        executeRql(rqlPresets.s3_public);
      }
    });
  }

  // 3. Accessible Clipboard Copy
  function bindCopyButtons() {
    const copyBtns = document.querySelectorAll('.copy-btn');
    copyBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.getAttribute('data-copy');
        if (text) {
          navigator.clipboard.writeText(text).then(() => {
            const originalText = btn.textContent;
            btn.textContent = 'COPIED!';
            btn.style.borderColor = 'var(--accent-ink)';
            setTimeout(() => {
              btn.textContent = originalText;
              btn.style.borderColor = '';
            }, 1800);
          });
        }
      });
    });
  }

  bindCopyButtons();
});
