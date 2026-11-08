(function() {
  // DOM elements
  const domainInput = document.getElementById('domainInput');
  const checkBtn = document.getElementById('checkBtn');
  const btnText = document.getElementById('btnText');
  const btnLoader = document.getElementById('btnLoader');
  const resultContainer = document.getElementById('resultContainer');
  const placeholderState = document.getElementById('placeholderState');
  const recordsContainer = document.getElementById('recordsContainer');
  const errorContainer = document.getElementById('errorContainer');

  // Tab elements
  const tabGenerate = document.getElementById('tabGenerate');
  const tabMechanisms = document.getElementById('tabMechanisms');
  const tabBestPractices = document.getElementById('tabBestPractices');
  const tabTools = document.getElementById('tabTools');
  const generateTab = document.getElementById('generateTab');
  const mechanismsTab = document.getElementById('mechanismsTab');
  const bestPracticesTab = document.getElementById('bestPracticesTab');
  const toolsTab = document.getElementById('toolsTab');

  // Generator elements
  const genIp4 = document.getElementById('genIp4');
  const genInclude = document.getElementById('genInclude');
  const genPolicy = document.getElementById('genPolicy');
  const generatedSpf = document.getElementById('generatedSpf');
  const copySpfBtn = document.getElementById('copySpfBtn');

  // Tab switching
  function switchTab(activeTab, activeContent) {
    [tabGenerate, tabMechanisms, tabBestPractices, tabTools].forEach(t => t.classList.remove('active'));
    [generateTab, mechanismsTab, bestPracticesTab, toolsTab].forEach(t => t.classList.remove('active'));
    
    [tabGenerate, tabMechanisms, tabBestPractices, tabTools].forEach(t => t.setAttribute('aria-selected', t === activeTab ? 'true' : 'false'));
    activeTab.classList.add('active');
    activeContent.classList.add('active');
  }

  if (tabGenerate) {
    tabGenerate.addEventListener('click', () => switchTab(tabGenerate, generateTab));
  }
  if (tabMechanisms) {
    tabMechanisms.addEventListener('click', () => switchTab(tabMechanisms, mechanismsTab));
  }
  if (tabBestPractices) {
    tabBestPractices.addEventListener('click', () => switchTab(tabBestPractices, bestPracticesTab));
  }
  if (tabTools) {
    tabTools.addEventListener('click', () => switchTab(tabTools, toolsTab));
  }

  // Update SPF generator preview
  function updateSpfPreview() {
    let spf = 'v=spf1';
    
    if (genIp4 && genIp4.value.trim()) {
      const ips = genIp4.value.trim().split(/[,\s]+/);
      ips.forEach(ip => {
        if (ip) spf += ` ip4:${ip}`;
      });
    }
    
    if (genInclude && genInclude.value.trim()) {
      const includes = genInclude.value.trim().split(/[,\s]+/);
      includes.forEach(inc => {
        if (inc) spf += ` include:${inc}`;
      });
    }
    
    if (genPolicy) {
      spf += ` ${genPolicy.value}`;
    } else {
      spf += ' -all';
    }
    
    if (generatedSpf) {
      generatedSpf.textContent = spf;
    }
  }

  if (genIp4) genIp4.addEventListener('input', updateSpfPreview);
  if (genInclude) genInclude.addEventListener('input', updateSpfPreview);
  if (genPolicy) genPolicy.addEventListener('change', updateSpfPreview);
  
  if (copySpfBtn) {
    copySpfBtn.addEventListener('click', () => {
      if (generatedSpf) {
      const status = document.getElementById('copyStatus');
      const done = ok => {
        if (!status) return;
        status.textContent = ok ? 'Copied to clipboard' : 'Copy failed, select the record and copy it manually';
        clearTimeout(done.t);
        done.t = setTimeout(() => { status.textContent = ''; }, 2500);
      };
      navigator.clipboard.writeText(generatedSpf.textContent).then(() => done(true), () => done(false));
      }
    });
  }

  // Helper functions
  function setActiveView(view) {
    if (placeholderState) placeholderState.hidden = view !== 'placeholder';
    if (recordsContainer) recordsContainer.hidden = view !== 'records';
    if (errorContainer) errorContainer.hidden = view !== 'error';
  }

  setActiveView('placeholder');

  // Parse SPF mechanisms
  function parseSPF(record) {
    const mechanisms = [];
    // Remove any quotes and split by spaces
    const cleanRecord = record.replace(/^"|"$/g, '');
    const parts = cleanRecord.split(' ');
    
    parts.forEach(part => {
      part = part.trim();
      if (part && !part.startsWith('v=spf1')) {
        mechanisms.push(part);
      }
    });
    
    return mechanisms;
  }

  // Count DNS lookups in SPF record
  function countLookups(record) {
    let count = 0;
    const mechanisms = parseSPF(record);
    
    mechanisms.forEach(mech => {
      if (mech.startsWith('include:') || 
          mech.startsWith('a:') || 
          mech.startsWith('mx:') || 
          mech.startsWith('redirect=')) {
        count++;
      }
    });
    
    return count;
  }

  // Check for deprecated PTR
  function hasPTR(record) {
    return record.includes('ptr');
  }

  // Check for hard fail
  function hasHardFail(record) {
    return record.includes('-all');
  }

  // Validate SPF record
  function validateSPF(record) {
    const validation = {
      valid: true,
      lookupCount: 0,
      warnings: [],
      errors: []
    };

    // Count DNS lookups
    validation.lookupCount = countLookups(record);

    if (validation.lookupCount > 10) {
      validation.valid = false;
      validation.errors.push(`Exceeds 10 DNS lookup limit (${validation.lookupCount} lookups)`);
    }

    // Check for deprecated PTR
    if (hasPTR(record)) {
      validation.warnings.push('PTR mechanism is deprecated and should not be used');
    }

    // Check for hard fail
    if (!hasHardFail(record)) {
      validation.warnings.push('Consider using -all (hard fail) for stronger security');
    }

    return validation;
  }

  // Render SPF result
  function checkRow(cls, word, text) {
    return `<li class="${cls}"><span class="word">${word}</span><span class="what">${escapeHtml(text)}</span></li>`;
  }

  function renderSPFResult(domain, record) {
    const mechanisms = parseSPF(record);
    const validation = validateSPF(record);

    const mechanismsHtml = mechanisms.map(m => `<span class="mech">${escapeHtml(m)}</span>`).join('');

    let checks = '';
    checks += validation.valid
      ? checkRow('ok', 'Pass', 'Valid SPF record')
      : checkRow('fail', 'Fail', 'Invalid SPF record');
    checks += checkRow('info', 'Info', `DNS lookups: ${validation.lookupCount}/10`);
    validation.errors.forEach(err => { checks += checkRow('fail', 'Fail', err); });
    validation.warnings.forEach(w => { checks += checkRow('warn', 'Warning', w); });

    if (recordsContainer) {
      recordsContainer.innerHTML = `
        <div class="state ${validation.valid ? 'ok' : 'fail'}">
          <h3 class="state-title">${validation.valid ? 'Valid SPF record' : 'Invalid SPF record'}</h3>
          <span class="badge-domain">${escapeHtml(domain)}</span>
          <p class="query">DNS lookup: ${escapeHtml(domain)} IN TXT</p>
          <div class="mech-list">${mechanismsHtml}</div>
          <ul class="checks">${checks}</ul>
          <div class="record-card">${escapeHtml(record)}</div>
        </div>
      `;
    }
  }

  function escapeHtml(unsafe) {
    if (!unsafe) return '';
return String(unsafe).replace(/[&<>"']/g, function(m) {
      if (m === '&') return '&amp;';
      if (m === '<') return '&lt;';
      if (m === '>') return '&gt;';
if (m === '"') return '&quot;';
      if (m === "'") return '&#39;';
      return m;
    });
  }

  function setLoading(isLoading) {
    if (checkBtn) checkBtn.disabled = isLoading;
    if (btnText) btnText.textContent = isLoading ? 'Checking' : 'Check SPF';
    if (btnLoader) {
btnLoader.hidden = !isLoading;
      btnLoader.className = isLoading ? 'loader' : '';
    }
  }

  // SPF lookup function - FIXED VERSION
  async function querySPF(domain) {
    let cleanDomain = domain.trim().replace(/\.+$/, '');
    if (!cleanDomain) throw new Error('Please enter a domain');
    
    
    const url = `https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=TXT`;
    
    const response = await fetch(url);
    if (!response.ok) throw new Error(`DNS query failed (HTTP ${response.status})`);
    
    const data = await response.json();
    
    if (data.Status === 3) {
      throw new Error(`Domain "${cleanDomain}" does not exist`);
    } else if (data.Status !== 0) {
      const reason = data.Comment || `DNS error code ${data.Status}`;
      throw new Error(`DNS lookup error: ${reason}`);
    }
    
    const answers = data.Answer || [];
    
    // Find SPF records (TXT records containing v=spf1)
    const spfRecords = answers.filter(r => {
      if (r.type === 16 && r.data) {
        // Remove quotes and check for v=spf1
        const txt = r.data.replace(/^"|"$/g, '');
        return txt.startsWith('v=spf1');
      }
      return false;
    });
    
    
    if (spfRecords.length === 0) {
      throw new Error(`No SPF record found for "${cleanDomain}"`);
    }
    
    if (spfRecords.length > 1) {
      throw new Error(`Multiple SPF records found - this will cause "permerror"`);
    }
    
    // Clean up the record
    let record = spfRecords[0].data.replace(/^"|"$/g, '');
    
    return {
      domain: cleanDomain,
      record: record,
      raw: spfRecords[0]
    };
  }

  // Main lookup function
  async function performLookup() {
    if (!domainInput) return;
    
    const domain = domainInput.value.trim();
    
    if (!domain) {
      setActiveView('error');
      if (errorContainer) {
errorContainer.innerHTML = `
          <div class="state fail">
            <h3 class="state-title">Fail: missing information</h3>
            <p>Please enter a domain.</p>
          </div>
        `;
      }
      return;
    }
    
    setLoading(true);
    try {
      const result = await querySPF(domain);
      renderSPFResult(result.domain, result.record);
      setActiveView('records');
    } catch (err) {
      console.error('SPF lookup error:', err);
      if (errorContainer) {
errorContainer.innerHTML = `
          <div class="state fail">
            <h3 class="state-title">Fail: error checking SPF</h3>
            <p>${escapeHtml(err.message)}</p>
          </div>
        `;
      }
      setActiveView('error');
    } finally {
      setLoading(false);
    }
  }

  // Event listeners
  if (checkBtn) {
    checkBtn.addEventListener('click', performLookup);
  }
  
  if (domainInput) {
    domainInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') performLookup();
    });
  }

  // Handle URL parameters
  function handleUrlParameter() {
    if (!domainInput) return;
    
    const urlParams = new URLSearchParams(window.location.search);
    const domainParam = urlParams.get('domain');
    
    if (domainParam) {
      domainInput.value = domainParam;
      // Small delay to ensure DOM is ready
      setTimeout(() => performLookup(), 100);
    }
  }

  window.addEventListener('load', handleUrlParameter);
})();
