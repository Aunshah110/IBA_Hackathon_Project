(function () {
  const btn      = document.getElementById('getGps');
  const useSch   = document.getElementById('useSchoolGps');
  const statusEl = document.getElementById('gpsStatus');
  const latEl    = document.getElementById('gpsLat');
  const lngEl    = document.getElementById('gpsLng');
  if (!btn || !statusEl) return;

  function setOk(lat, lng, label) {
    latEl.value = lat.toFixed(6);
    lngEl.value = lng.toFixed(6);
    statusEl.className = 'pill ok';
    statusEl.innerHTML = `<span class="dot"></span>${label}: ${lat.toFixed(5)}, ${lng.toFixed(5)}`;
    document.dispatchEvent(new CustomEvent('gsds:step', { detail: { step: 2 } }));
  }
  function setErr(msg) {
    statusEl.className = 'pill bad';
    statusEl.innerHTML = `<span class="dot"></span>${msg}`;
  }

  btn.addEventListener('click', () => {
    if (!navigator.geolocation) return setErr('Geolocation unsupported');
    statusEl.className = 'pill warn';
    statusEl.innerHTML = '<span class="dot"></span>Locating…';
    navigator.geolocation.getCurrentPosition(
      p => setOk(p.coords.latitude, p.coords.longitude, 'GPS'),
      e => setErr('GPS error: ' + e.message),
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  });

  if (useSch) {
    useSch.addEventListener('click', () => {
      setOk(parseFloat(useSch.dataset.lat), parseFloat(useSch.dataset.lng), 'School (demo)');
    });
  }
})();