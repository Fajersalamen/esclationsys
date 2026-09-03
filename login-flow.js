// Login page background: particles flow in from the left and right edges
// along bezier paths and converge on the center, where the login card sits.
// Plain 2D canvas (unlike the old login-moon.js, no WebGL/Three.js needed) -
// so there's no heavy library to lazily import, but the animation loop
// itself still only runs while the login gate is actually visible: an
// already-logged-in visitor (the common case - sessions persist) never
// pays for it past the first frame.

(function () {
  const canvas = document.getElementById('loginFlowCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const loginGate = document.getElementById('loginGate');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let W, H, DPR, paths = [];
  let explosions = [];
  let running = false;
  let rafId = null;

  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = W * DPR;
    canvas.height = H * DPR;
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }

  function seed() {
    resize();
    // Scales with viewport area like the app's other ambient canvas
    // (orbitCanvasHome) - more paths on a big monitor, fewer on a phone.
    const count = Math.max(24, Math.min(90, Math.round((W * H) / 22000)));
    paths = [];
    for (let i = 0; i < count; i++) {
      paths.push({
        fromLeft: i % 2 === 0,
        startY: (i / count) * H * 1.4 - H * 0.2,
        t: Math.random(),
        speed: 0.0015 + Math.random() * 0.002,
      });
    }
  }

  function bezierPoint(t, p0, p1, p2, p3) {
    const u = 1 - t;
    return {
      x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
      y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
    };
  }

  function step() {
    if (!running) return;
    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H / 2;

    explosions.forEach((e) => { e.radius += 14; e.life -= 0.018; });
    explosions = explosions.filter((e) => e.life > 0);

    for (const path of paths) {
      const p0 = { x: path.fromLeft ? 0 : W, y: path.startY };
      const p1 = { x: path.fromLeft ? cx * 0.5 : W - cx * 0.5, y: path.startY };
      const p2 = { x: path.fromLeft ? cx * 0.8 : W - cx * 0.8, y: cy };
      const p3 = { x: cx, y: cy };

      ctx.beginPath();
      ctx.moveTo(p0.x, p0.y);
      ctx.bezierCurveTo(p1.x, p1.y, p2.x, p2.y, p3.x, p3.y);
      ctx.strokeStyle = 'rgba(148, 210, 214, 0.16)';
      ctx.lineWidth = 1;
      ctx.setLineDash([1, 4]);
      ctx.stroke();
      ctx.setLineDash([]);

      path.t += path.speed;
      if (path.t > 1) {
        path.t = 0;
        path.startY += (Math.random() - 0.5) * 10;
      }
      let pos = bezierPoint(path.t, p0, p1, p2, p3);

      let dx = 0, dy = 0;
      for (const e of explosions) {
        const ddx = pos.x - e.x, ddy = pos.y - e.y;
        const dist = Math.hypot(ddx, ddy);
        if (dist < e.radius + 120 && dist > e.radius - 120) {
          const force = (1 - Math.abs(dist - e.radius) / 120) * e.life;
          dx += (ddx / dist) * force * 80;
          dy += (ddy / dist) * force * 80;
        }
      }
      pos.x += dx;
      pos.y += dy;

      ctx.fillStyle = 'rgba(180, 226, 230, 0.85)';
      ctx.fillRect(pos.x - 1.5, pos.y - 1.5, 3, 3);
    }

    rafId = requestAnimationFrame(step);
  }

  function start() {
    if (running || reduceMotion) return;
    running = true;
    if (!paths.length) seed();
    rafId = requestAnimationFrame(step);
  }
  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  window.addEventListener('resize', () => { if (running) seed(); });
  window.addEventListener('click', (e) => {
    if (!running) return;
    explosions.push({ x: e.clientX, y: e.clientY, radius: 0, life: 1 });
  });

  if (loginGate && !loginGate.classList.contains('hide')) start();
  if (loginGate) {
    new MutationObserver(() => {
      if (loginGate.classList.contains('hide')) stop();
      else start();
    }).observe(loginGate, { attributes: true, attributeFilter: ['class'] });
  }
})();
