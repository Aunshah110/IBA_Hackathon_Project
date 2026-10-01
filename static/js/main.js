(function () {
  // ---- Toast host ----
  const host = document.getElementById('toast-host');

  function toast(title, body, tone = 'info', ms = 4000) {
    if (!host) return;
    const el = document.createElement('div');
    el.className = `toast ${tone}`;
    el.innerHTML = `<div class="t-title">${title}</div><div>${body || ''}</div>`;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .3s, transform .3s';
      el.style.opacity = '0'; el.style.transform = 'translateX(20px)';
      setTimeout(() => el.remove(), 320);
    }, ms);
  }

  // ---- Structured verify-result banner (HCI feedback & closure #12) ----
  const vr = document.getElementById('verifyResult');
  if (vr) {
    try {
      const d = JSON.parse(vr.dataset.payload);
      const ok = d.result === 'verified';
      const banner = document.createElement('div');
      banner.className = `banner ${ok ? 'ok' : 'bad'}`;
      banner.setAttribute('role', ok ? 'status' : 'alert');
      banner.innerHTML = `
        <span class="banner-icon" aria-hidden="true">${ok ? '✓' : '!'}</span>
        <div class="banner-body">
          <div class="banner-title">
            ${ok ? 'Verification complete' : 'Verification flagged'}
            — ${d.school_name}
          </div>
          <div>
            Detected <strong>${d.detected}</strong> faces ·
            declared <strong>${d.declared}</strong> ·
            ${d.distance_m} m from school.
            ${d.reasons.length ? '<br>Issues: ' + d.reasons.join(', ') : ''}
          </div>
          <div class="mt-4">
            <a class="btn" href="/school/${d.school_id}">View inspection</a>
            <a class="btn primary" href="/dashboard">Next school →</a>
          </div>
        </div>`;
      const main = document.getElementById('main');
      main.insertBefore(banner, main.firstChild);
      toast(ok ? 'Verification recorded' : 'Flagged for follow-up',
            d.school_name, ok ? 'ok' : 'bad');
    } catch (_) { /* noop */ }
  }

  // ---- Auto-dismiss standard flashes as toasts ----
  document.querySelectorAll('.banner.ok, .banner.bad').forEach(el => {
    if (el.id === 'submitHint') return;
    // leave them; they're informative. No auto-dismiss.
  });

  // ---- Keyboard shortcut: / = focus first input; g d = dashboard ----
  document.addEventListener('keydown', e => {
    if (e.target.matches('input, textarea, select')) return;
    if (e.key === '/') {
      const i = document.querySelector('input:not([type=hidden]), select, textarea');
      if (i) { e.preventDefault(); i.focus(); }
    }
  });

  // expose for other scripts
  window.GSDS = { toast };
})();