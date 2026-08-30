// Login page hero: a realistic moon with a click-to-reveal particle ring and
// asteroid belt. A plain Three.js port of a React-Three-Fiber component — this
// project has no React/JSX pipeline, so the scene graph is built imperatively
// instead of declaratively, but the math, shaders, and animation are the same.
//
// Three.js (plus a moon texture, a 60,000-particle shader system, and 75
// instanced asteroids) is only ever needed for the brief moment a visitor is
// actually looking at the login screen — for an already-logged-in visitor
// (the common case: sessions persist, so most page loads never show this
// screen at all) it used to load and build the whole scene anyway, every
// single time, and just pause its render loop afterward. That's the
// difference between "skip rendering a hidden thing" and "never fetch/build
// it at all" — this file now does the latter: it waits until it actually
// knows the login screen will be shown before importing Three.js at all.

const canvas = document.getElementById('loginMoonCanvas');

if (canvas) {
  const loginGate = document.getElementById('loginGate');
  const isAlreadyPastLogin = () => !!(loginGate && loginGate.classList.contains('hide'));

  if (!isAlreadyPastLogin()) {
    let decided = false;
    let observer = null;
    if (loginGate) {
      observer = new MutationObserver(() => {
        if (loginGate.classList.contains('hide')) {
          decided = true;
          observer.disconnect();
        }
      });
      observer.observe(loginGate, { attributes: true, attributeFilter: ['class'] });
    }
    // A brief grace period for app.js's async Supabase session check to
    // resolve, in case it just hasn't finished yet (e.g. a slow connection)
    // — avoids loading the whole 3D scene for an already-logged-in visitor
    // just because the auth check hadn't confirmed that yet at this exact
    // moment. Genuinely logged-out visitors pay this once, up front.
    setTimeout(() => {
      if (observer) observer.disconnect();
      if (!decided) initMoonScene();
    }, 350);
  }

  async function initMoonScene() {
    const THREE = await import('https://cdn.jsdelivr.net/npm/three@0.160.0/+esm');
    const { OrbitControls } = await import('https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/controls/OrbitControls.js/+esm');

    const panel = canvas.closest('.login-image-panel');
    const RADIUS = 2.0;
    const MOON_TEXTURE_URL = 'https://raw.githubusercontent.com/mrdoob/three.js/master/examples/textures/planets/moon_1024.jpg';

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    camera.position.set(0, 4, 10);

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableZoom = false;
    controls.enablePan = false;
    controls.autoRotate = false;

    scene.add(new THREE.AmbientLight(0xffffff, 0.15));
    const keyLight = new THREE.DirectionalLight(0xffffff, 1.5);
    keyLight.position.set(8, 5, 5);
    keyLight.castShadow = true;
    keyLight.shadow.mapSize.set(2048, 2048);
    scene.add(keyLight);
    const rimLight = new THREE.DirectionalLight(0x4a90e2, 0.3);
    rimLight.position.set(-5, -3, -5);
    scene.add(rimLight);

    const group = new THREE.Group();
    group.rotation.x = Math.PI / 8;
    scene.add(group);

    const textureLoader = new THREE.TextureLoader();
    const moonTexture = textureLoader.load(MOON_TEXTURE_URL);

    const moon = new THREE.Mesh(
      new THREE.SphereGeometry(RADIUS, 64, 64),
      new THREE.MeshStandardMaterial({ map: moonTexture, bumpMap: moonTexture, bumpScale: 0.02, roughness: 0.8, metalness: 0.1 })
    );
    moon.castShadow = true;
    moon.receiveShadow = true;
    group.add(moon);

    // ----- Particle ring: a dust ring that "spawns" out of the moon's surface
    // when clicked, swirling into place. Positions/colors are precomputed once. -----
    const PARTICLE_COUNT = 60000;
    const ringPositions = new Float32Array(PARTICLE_COUNT * 3);
    const ringColors = new Float32Array(PARTICLE_COUNT * 3);
    const ringRandoms = new Float32Array(PARTICLE_COUNT);

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const angle = Math.random() * Math.PI * 2;
      const rDist = Math.pow(Math.random(), 1.5);
      const radius = 2.2 + rDist * 2.2;
      const thickness = 0.4 - rDist * 0.2;
      const ySpread = Math.random() + Math.random() + Math.random() - 1.5;
      const y = ySpread * thickness;

      ringPositions[i * 3] = Math.cos(angle) * radius;
      ringPositions[i * 3 + 1] = y;
      ringPositions[i * 3 + 2] = Math.sin(angle) * radius;

      const intensity = 1.0 - rDist;
      const paletteType = Math.random();
      let baseR, baseG, baseB;
      if (paletteType < 0.8) { baseR = 0.25; baseG = 0.3; baseB = 0.35; }
      else if (paletteType < 0.92) { baseR = 0.0; baseG = 0.6; baseB = 0.8; }
      else { baseR = 0.6; baseG = 0.2; baseB = 0.8; }
      baseR = Math.min(1, Math.max(0, baseR + (Math.random() - 0.5) * 0.1));
      baseG = Math.min(1, Math.max(0, baseG + (Math.random() - 0.5) * 0.1));
      baseB = Math.min(1, Math.max(0, baseB + (Math.random() - 0.5) * 0.1));
      const sparkle = Math.random() > 0.95 ? 2.5 : 1.0;

      ringColors[i * 3] = baseR * intensity * sparkle;
      ringColors[i * 3 + 1] = baseG * intensity * sparkle;
      ringColors[i * 3 + 2] = baseB * intensity * sparkle;
      ringRandoms[i] = Math.random();
    }

    const ASTEROID_COUNT = 75;
    const ringUniforms = {
      uProgress: { value: 0 },
      uAsteroids: { value: new Float32Array(ASTEROID_COUNT * 4) },
      time: { value: 0 },
    };

    const ringGeometry = new THREE.BufferGeometry();
    ringGeometry.setAttribute('position', new THREE.BufferAttribute(ringPositions, 3));
    ringGeometry.setAttribute('color', new THREE.BufferAttribute(ringColors, 3));
    ringGeometry.setAttribute('aRandom', new THREE.BufferAttribute(ringRandoms, 1));

    const ringMaterial = new THREE.PointsMaterial({
      size: 0.008, vertexColors: true, transparent: true, opacity: 0.8,
      sizeAttenuation: true, blending: THREE.AdditiveBlending, depthWrite: false,
    });
    ringMaterial.onBeforeCompile = (shader) => {
      shader.uniforms.uProgress = ringUniforms.uProgress;
      shader.uniforms.uAsteroids = ringUniforms.uAsteroids;
      shader.uniforms.time = ringUniforms.time;

      shader.vertexShader = `
        uniform float uProgress;
        uniform vec4 uAsteroids[${ASTEROID_COUNT}];
        uniform float time;
        attribute float aRandom;
        varying float vProgress;
        ${shader.vertexShader}
      `;
      shader.vertexShader = shader.vertexShader.replace(
        '#include <begin_vertex>',
        `
        vec3 transformed = vec3(position);

        float angle = atan(transformed.x, transformed.z);
        float normalizedAngle = abs(angle) / 3.14159265359;
        float spawnThreshold = 1.0 - normalizedAngle;

        float progressValue = (uProgress * 1.4) - spawnThreshold;
        float particleProgress = smoothstep(0.0, 0.4, progressValue);
        vProgress = particleProgress;

        transformed.y += sin(angle * 10.0 + time) * 0.05 * aRandom;

        if (uProgress > 0.5) {
          for (int i = 0; i < ${ASTEROID_COUNT}; i++) {
            vec4 astData = uAsteroids[i];
            vec3 delta = transformed - astData.xyz;
            float dist = length(delta);
            float rad = astData.w * 2.0 + 0.15;
            if (dist < rad) {
              float force = pow((rad - dist) / rad, 2.0);
              transformed += normalize(delta) * force * 0.4;
              transformed.y += force * 0.20 * (aRandom - 0.5);
            }
          }
        }

        float swirl = (1.0 - particleProgress) * 4.0;
        float s = sin(swirl);
        float c = cos(swirl);
        transformed.xz = mat2(c, -s, s, c) * transformed.xz;

        transformed.y += (1.0 - particleProgress) * (transformed.y >= 0.0 ? 1.0 : -1.0);

        vec3 moonSurface = normalize(transformed) * 2.1;
        transformed = mix(moonSurface, transformed, particleProgress);
        `
      );
      shader.fragmentShader = `
        varying float vProgress;
        ${shader.fragmentShader}
      `;
      shader.fragmentShader = shader.fragmentShader.replace(
        '#include <color_fragment>',
        `
        #include <color_fragment>
        diffuseColor.a *= vProgress;
        `
      );
    };

    const ring = new THREE.Points(ringGeometry, ringMaterial);
    ring.rotation.x = -Math.PI / 2;
    group.add(ring);

    // ----- Asteroid belt: a handful of larger rocks orbiting at varying radii,
    // whose positions also drive the ring's "avoidance" deformation above. -----
    function generateAsteroids(count) {
      const list = [];
      for (let i = 0; i < count; i++) {
        const baseRadius = 2.8 + Math.random() * 2.0;
        const radialAmplitude = 0.5 + Math.random() * 1.5;
        const radialSpeed = 0.15 + Math.random() * 0.25;
        const phase = Math.random() * Math.PI * 2;
        const angle = Math.random() * Math.PI * 2;
        const zOffset = (Math.random() - 0.5) * 0.8;
        const speed = (0.04 + Math.random() * 0.08) * (Math.random() > 0.5 ? 1 : -1);
        const scale = 0.02 + Math.pow(Math.random(), 4) * 0.18;
        list.push({
          angle, baseRadius, radialAmplitude, radialSpeed, phase, zOffset, speed,
          rx: Math.random() * Math.PI, ry: Math.random() * Math.PI, rz: Math.random() * Math.PI,
          rsx: (Math.random() - 0.5) * 0.05, rsy: (Math.random() - 0.5) * 0.05, rsz: (Math.random() - 0.5) * 0.05,
          scale,
        });
      }
      list.sort((a, b) => b.scale - a.scale);
      return list;
    }

    const asteroids = generateAsteroids(ASTEROID_COUNT);
    const asteroidMesh = new THREE.InstancedMesh(
      new THREE.DodecahedronGeometry(1, 0),
      new THREE.MeshStandardMaterial({ map: moonTexture, bumpMap: moonTexture, bumpScale: 0.08, color: 0xffffff, roughness: 0.7, metalness: 0.1 }),
      ASTEROID_COUNT
    );
    asteroidMesh.castShadow = true;
    asteroidMesh.receiveShadow = true;
    group.add(asteroidMesh);

    const dummy = new THREE.Object3D();
    const massiveAsteroids = new Float32Array(ASTEROID_COUNT * 4);
    let asteroidScale = 0;

    // ----- State machine: hidden -> animating -> visible, started by clicking the moon -----
    let ringState = 'hidden';
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    renderer.domElement.addEventListener('click', (event) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      if (raycaster.intersectObject(moon).length && ringState === 'hidden') {
        ringState = 'animating';
      }
    });
    renderer.domElement.addEventListener('pointermove', (event) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      renderer.domElement.style.cursor = raycaster.intersectObject(moon).length ? 'pointer' : 'auto';
    });

    function resize() {
      const w = panel ? panel.clientWidth : canvas.clientWidth;
      const h = panel ? panel.clientHeight : canvas.clientHeight;
      if (!w || !h) return;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h, false);
    }
    resize();
    new ResizeObserver(resize).observe(panel || canvas);

    // Pauses while the login gate is hidden (post sign-in) so it doesn't keep
    // rendering/costing GPU in the background for the rest of the session.
    let running = true;
    if (loginGate) {
      new MutationObserver(() => { running = !loginGate.classList.contains('hide'); })
        .observe(loginGate, { attributes: true, attributeFilter: ['class'] });
    }

    const clock = new THREE.Clock();
    function animate() {
      requestAnimationFrame(animate);
      if (!running) return;
      const delta = Math.min(clock.getDelta(), 0.1);

      moon.rotation.y += delta * 0.05;
      ring.rotation.y -= delta * 0.02;
      ring.updateMatrix();

      const invMat = new THREE.Matrix4().copy(ring.matrix).invert();
      const localAsteroids = new Float32Array(ASTEROID_COUNT * 4);
      for (let i = 0; i < ASTEROID_COUNT; i++) {
        const v = new THREE.Vector3(massiveAsteroids[i * 4], massiveAsteroids[i * 4 + 1], massiveAsteroids[i * 4 + 2]);
        v.applyMatrix4(invMat);
        localAsteroids[i * 4] = v.x;
        localAsteroids[i * 4 + 1] = v.y;
        localAsteroids[i * 4 + 2] = v.z;
        localAsteroids[i * 4 + 3] = massiveAsteroids[i * 4 + 3];
      }
      ringUniforms.uAsteroids.value = localAsteroids;
      ringUniforms.time.value = clock.elapsedTime;

      if (ringState === 'animating') {
        ringUniforms.uProgress.value = Math.min(1, ringUniforms.uProgress.value + delta * 0.35);
        if (ringUniforms.uProgress.value >= 1) ringState = 'visible';
      } else if (ringState === 'visible') {
        ringUniforms.uProgress.value = 1;
      } else {
        ringUniforms.uProgress.value = 0;
      }

      const targetScale = ringState === 'hidden' ? 0 : 1;
      const lerpSpeed = ringState === 'hidden' ? 5 : 2;
      asteroidScale = THREE.MathUtils.lerp(asteroidScale, targetScale, delta * lerpSpeed);
      asteroidMesh.visible = asteroidScale >= 0.01;
      if (asteroidMesh.visible) {
        asteroids.forEach((ast, i) => {
          ast.angle += ast.speed * delta;
          ast.phase += ast.radialSpeed * delta;
          let currentRadius = ast.baseRadius + Math.sin(ast.phase) * ast.radialAmplitude;
          if (currentRadius < 2.15) currentRadius = 2.15 + (2.15 - currentRadius) * 0.85;
          const x = Math.cos(ast.angle) * currentRadius;
          const y = Math.sin(ast.angle) * currentRadius;
          massiveAsteroids[i * 4] = x;
          massiveAsteroids[i * 4 + 1] = y;
          massiveAsteroids[i * 4 + 2] = ast.zOffset;
          massiveAsteroids[i * 4 + 3] = ast.scale;
          ast.rx += ast.rsx; ast.ry += ast.rsy; ast.rz += ast.rsz;
          dummy.position.set(x, y, ast.zOffset);
          dummy.rotation.set(ast.rx, ast.ry, ast.rz);
          dummy.scale.setScalar(ast.scale * asteroidScale);
          dummy.updateMatrix();
          asteroidMesh.setMatrixAt(i, dummy.matrix);
        });
        asteroidMesh.instanceMatrix.needsUpdate = true;
      }

      controls.update();
      renderer.render(scene, camera);
    }
    animate();
  }
}
