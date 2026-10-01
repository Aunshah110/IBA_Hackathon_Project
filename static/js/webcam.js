(function () {
  const video  = document.getElementById('cam');
  const canvas = document.getElementById('canvas');
  const preview= document.getElementById('preview');
  const ph     = document.getElementById('camPlaceholder');
  const start  = document.getElementById('startCam');
  const snap   = document.getElementById('snap');
  const status = document.getElementById('camStatus');
  const form   = document.getElementById('verifyForm');
  const fpBtn  = document.getElementById('scanFp');
  const fpStat = document.getElementById('fpStatus');
  const fpTok  = document.getElementById('fpToken');
  const submitBtn = document.getElementById('submitBtn');
  const hintBox   = document.getElementById('submitHint');
  const reasonsUl = document.getElementById('submitReasons');

  if (!form) return;

  let stream = null;
  let blob = null;
  const state = { fp: false, gps: false, snap: false };

  function refreshGate() {
    const missing = [];
    if (!state.fp)   missing.push('Scan fingerprint');
    if (!state.gps)  missing.push('Capture location');
    if (!state.snap) missing.push('Take snapshot');

    if (missing.length === 0) {
      submitBtn.disabled = false;
      submitBtn.setAttribute('aria-disabled', 'false');
      submitBtn.title = 'All checks ready';
      hintBox.style.display = 'none';
    } else {
      submitBtn.disabled = true;
      submitBtn.setAttribute('aria-disabled', 'true');
      hintBox.style.display = '';
      reasonsUl.innerHTML = missing.map(m => `<li>${m}</li>`).join('');
    }
  }

  // ---- Step 1: fingerprint (simulated) ----
  if (fpBtn) fpBtn.addEventListener('click', () => {
    fpTok.value = 'DEMO_TEACHER_FP';
    fpStat.className = 'pill ok';
    fpStat.innerHTML = '<span class="dot"></span>Scanned';
    state.fp = true;
    markStep(1);
    refreshGate();
  });

  // ---- Step 2 completion driven by geolocation.js event ----
  document.addEventListener('gsds:step', e => {
    if (e.detail.step === 2) { state.gps = true; markStep(2); refreshGate(); }
  });

  // ---- Step 3: camera ----
  if (start) start.addEventListener('click', async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } });
      video.srcObject = stream;
      if (ph) ph.style.display = 'none';
      snap.disabled = false;
    } catch (e) {
      alert('Camera error: ' + e.message);
    }
  });

  if (snap) snap.addEventListener('click', () => {
    if (!stream) return;
    canvas.width  = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob(b => {
      blob = b;
      preview.src = URL.createObjectURL(b);
      preview.style.display = 'block';
      video.style.display = 'none';
      status.className = 'pill ok';
      status.innerHTML = '<span class="dot"></span>Snapshot ready';
      state.snap = true;
      markStep(3);
      refreshGate();
    }, 'image/jpeg', 0.85);
  });

  // ---- Step 4: declared count entered ----
  const declared = form.querySelector('input[name="declared_students"]');
  if (declared) declared.addEventListener('input', () => markStep(4, declared.value !== ''));

  // ---- Inject snapshot just before submit ----
  form.addEventListener('submit', e => {
    if (!state.fp || !state.gps || !state.snap) { e.preventDefault(); return; }
    if (blob) {
      const dt = new DataTransfer();
      dt.items.add(new File([blob], 'snapshot.jpg', { type: 'image/jpeg' }));
      const inp = document.createElement('input');
      inp.type = 'file'; inp.name = 'snapshot'; inp.files = dt.files;
      inp.style.display = 'none';
      form.appendChild(inp);
    }
  });

  // ---- Stepper visuals ----
  function markStep(n, done = true) {
    const li = document.querySelector(`#stepper li[data-step="${n}"]`);
    if (!li) return;
    li.classList.toggle('done', done);
    li.classList.toggle('active', !done);
    // Next step becomes active
    const next = document.querySelector(`#stepper li[data-step="${n + 1}"]`);
    if (next && done) next.classList.add('active');
  }

  refreshGate();
})();