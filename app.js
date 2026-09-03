/* ============================================================
   Nova — Customer Service (FAJER AL SALAMEEN)
   app.js — منطق التطبيق + الاتصال بـ Supabase
   ملاحظة أمنية: كل الحماية الفعلية تتم عبر RLS Policies على
   مستوى قاعدة البيانات في Supabase — هذا الملف لا يعوّض عنها
   ولا يجب الاعتماد عليه وحده كطبقة أمان.
   ============================================================ */
  document.addEventListener('contextmenu', (e) => e.preventDefault());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) || (e.ctrlKey && e.key === 'u')) {
      e.preventDefault();
    }
  });

  // ====== Role / Permission Map ======
  // الصلاحيات هلأ بتجي من عمود role بجدول profiles على Supabase، مش من باسورد بالكود.
  // ضيف/عدّل رتب جديدة هون بس — الكود بياخدها أوتوماتيك.
  const ROLE_PERMISSIONS = {
    admin:       { isAdmin: true,  adminRole: 'full',    label: { ar: 'أدمن',       en: 'Admin' } },
    team_leader: { isAdmin: true,  adminRole: 'limited', label: { ar: 'تيم ليدر',    en: 'Team Leader' } },
    quality:     { isAdmin: false, adminRole: null,      label: { ar: 'كواليتي',     en: 'Quality' } },
    agent:       { isAdmin: false, adminRole: null,      label: { ar: 'موظف',       en: 'Agent' } }
  };
  const DEFAULT_ROLE = 'agent'; // إذا ما انلقى للمستخدم صف بجدول profiles

  const UPDATE_ARCHIVE_DAYS = 30; // updates older than this are auto-collapsed into the archive

  // New-hire onboarding journey: shown once per device to a user with no prior activity,
  // until they finish (or skip) it. Progress is tracked per-user in localStorage — steps
  // 'info'/'etiquette'/'training' are marked done on the relevant action; 'mentor'/'issue'
  // are derived live from the user's own real data, so they can't go stale.
  const ONBOARDING_STEP_DEFS = [
    { key: 'info', title: { ar: 'اقرأ المعلومات العامة', en: 'Read the general info' }, sub: { ar: 'أساسيات الشغل والسياسات', en: 'Work basics and policies' } },
    { key: 'etiquette', title: { ar: 'تصفّح بروتوكول المكالمة', en: 'Review the call etiquette' }, sub: { ar: 'كيف تبدأ وتنهي مكالمة صح', en: 'How to properly start and end a call' } },
    { key: 'training', title: { ar: 'جرّب سيناريو تدريبي واحد', en: 'Try one training scenario' }, sub: { ar: 'من مركز التدريب', en: 'From the Training Center' } },
    { key: 'mentor', title: { ar: 'اطلب راعي تدريب', en: 'Request a mentor' }, sub: { ar: 'حدا يتابع معك أول فترة', en: 'Someone to guide you early on' } },
    { key: 'issue', title: { ar: 'سجّل أول مشكلة تقنية', en: 'Log your first technical issue' }, sub: { ar: 'تدرّب على الأداة', en: 'Get familiar with the tool' } }
  ];
  let isAdmin = false;
  let adminRole = null; // 'full' | 'limited' | null
  let currentUserRole = null; // 'admin' | 'team_leader' | 'quality' | 'agent' ...
  let currentUserEmail = null;
  let activeCat = null;
  let renderSequence = 0;
  let previousVisibleCount = -1;
  let currentLang = localStorage.getItem('fajer_lang_v2') || 'en';

  // ====== Supabase Authentication ======
  // ⚠️ عدّل القيمتين التاليتين ببيانات مشروعك من Supabase:
  // Project Settings > API > Project URL و anon public key
  const SUPABASE_URL = "https://tyykcgsifuhsvlfwuzkb.supabase.co";
  const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR5eWtjZ3NpZnVoc3ZsZnd1emtiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU1NzExNDEsImV4cCI6MjEwMTE0NzE0MX0.QJhYVN1-YfVTuodG8VEe6o0BMM3uhKlCsj5ahCXaVnY";
  const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  let appBooted = false;
  let hasEverLoggedIn = false;

  // Public VAPID key for Web Push (safe to expose client-side — it's the public half of the
  // keypair; the private half lives only in the send-mentor-push Edge Function's secrets).
  const VAPID_PUBLIC_KEY = "BAp5BIOmonIpl1Nfk6_tUHYGsRMXVWXXOPZ7NUv6tRuhvXvcLSGxYt5gSKAscY-QOzPG0l2ouPvqO9UGhBzCLZg";

  function showLoginError(msg) {
    const el = document.getElementById('loginError');
    el.textContent = msg;
    el.style.display = 'block';
  }
  function hideLoginError() {
    document.getElementById('loginError').style.display = 'none';
  }
  function authErrorMessage(msg) {
    const map = {
      'Invalid login credentials': 'Incorrect email or password.',
      'Email not confirmed': 'This account needs email confirmation first.',
      'Too many requests': 'Too many attempts, try again later.'
    };
    return map[msg] || 'Login failed, please try again.';
  }

  // ====== Cloudflare Turnstile (bot/brute-force protection on the login card) ======
  // The actual verification happens server-side inside Supabase Auth (it holds the
  // secret key) — this only collects the token and hands it to signInWithPassword() /
  // resetPasswordForEmail(). Until CAPTCHA protection is turned on in the Supabase
  // dashboard, Supabase just ignores this token, so shipping this has zero effect on
  // login until that flip is made on their end.
  const TURNSTILE_SITE_KEY = '0x4AAAAAAEiJuT9Mbp7DSKSf';
  let turnstileWidgetId = null;
  let turnstileToken = null;
  function onTurnstileApiLoad() {
    const el = document.getElementById('turnstileWidget');
    if (!el || typeof turnstile === 'undefined') return;
    turnstileWidgetId = turnstile.render(el, {
      sitekey: TURNSTILE_SITE_KEY,
      theme: document.body.classList.contains('dark-mode') ? 'dark' : 'light',
      callback: (token) => { turnstileToken = token; },
      'expired-callback': () => { turnstileToken = null; },
      'error-callback': () => { turnstileToken = null; }
    });
  }
  function resetTurnstile() {
    turnstileToken = null;
    if (turnstileWidgetId !== null && typeof turnstile !== 'undefined') turnstile.reset(turnstileWidgetId);
  }
  // The login gate is only ever hidden with display:none, not removed from the
  // DOM - so without this, the Turnstile iframe (and whatever background bot-
  // detection work it keeps doing inside itself) stays alive for the rest of
  // the session after login, long after anyone can see or need it again.
  // turnstile.remove() fully tears the widget/iframe down.
  function destroyTurnstile() {
    if (turnstileWidgetId !== null && typeof turnstile !== 'undefined') {
      turnstile.remove(turnstileWidgetId);
      turnstileWidgetId = null;
    }
    turnstileToken = null;
  }

  // Spotlight effect on the login card: a soft glow that follows the cursor.
  const loginFormPanel = document.querySelector('.login-form-panel');
  if (loginFormPanel) {
    loginFormPanel.addEventListener('mousemove', function (e) {
      const rect = loginFormPanel.getBoundingClientRect();
      loginFormPanel.style.setProperty('--spot-x', (e.clientX - rect.left) + 'px');
      loginFormPanel.style.setProperty('--spot-y', (e.clientY - rect.top) + 'px');
    });
  }

  // Client-side brute-force friction: an escalating lockout on repeated failed logins
  // from this browser. This is a UX/defense-in-depth layer only — it lives in JS and
  // localStorage, so anyone hitting the Supabase Auth API directly (curl, a script)
  // bypasses it entirely. The real backstop against credential-stuffing/brute-force is
  // Supabase Auth's own server-side rate limiting on the token endpoint, which this
  // can't see or control from the client — see Project Settings > Authentication >
  // Rate Limits in the Supabase dashboard for that.
  const LOGIN_LOCKOUT_KEY = 'novaLoginLockout';
  const LOGIN_LOCKOUT_THRESHOLD = 5;   // failed attempts before any cooldown kicks in
  const LOGIN_LOCKOUT_STEPS_MS = [10000, 30000, 60000, 120000, 300000]; // escalating cooldowns, caps at 5 min
  let loginLockoutTimer = null;

  function readLoginLockoutState() {
    try {
      const raw = localStorage.getItem(LOGIN_LOCKOUT_KEY);
      return raw ? JSON.parse(raw) : { fails: 0, lockedUntil: 0 };
    } catch (e) { return { fails: 0, lockedUntil: 0 }; }
  }
  function writeLoginLockoutState(state) {
    try { localStorage.setItem(LOGIN_LOCKOUT_KEY, JSON.stringify(state)); } catch (e) { /* best-effort only */ }
  }
  function recordLoginFailure() {
    const state = readLoginLockoutState();
    state.fails += 1;
    if (state.fails >= LOGIN_LOCKOUT_THRESHOLD) {
      const stepIdx = Math.min(state.fails - LOGIN_LOCKOUT_THRESHOLD, LOGIN_LOCKOUT_STEPS_MS.length - 1);
      state.lockedUntil = Date.now() + LOGIN_LOCKOUT_STEPS_MS[stepIdx];
    }
    writeLoginLockoutState(state);
    return state;
  }
  function clearLoginLockout() {
    writeLoginLockoutState({ fails: 0, lockedUntil: 0 });
  }
  function applyLoginLockoutUI() {
    const state = readLoginLockoutState();
    const btn = document.getElementById('loginSubmitBtn');
    const text = document.getElementById('loginSubmitText');
    const remaining = state.lockedUntil - Date.now();
    if (loginLockoutTimer) { clearInterval(loginLockoutTimer); loginLockoutTimer = null; }
    if (remaining <= 0) {
      btn.disabled = false;
      return;
    }
    btn.disabled = true;
    const tick = () => {
      const left = Math.ceil((state.lockedUntil - Date.now()) / 1000);
      if (left <= 0) {
        clearInterval(loginLockoutTimer);
        loginLockoutTimer = null;
        btn.disabled = false;
        hideLoginError();
        return;
      }
      showLoginError(`Too many failed attempts — try again in ${left}s.`);
    };
    tick();
    loginLockoutTimer = setInterval(tick, 1000);
  }
  applyLoginLockoutUI();

  document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const lockState = readLoginLockoutState();
    if (lockState.lockedUntil > Date.now()) {
      applyLoginLockoutUI();
      return;
    }
    hideLoginError();
    const email = document.getElementById('loginEmail').value.trim();
    const pass = document.getElementById('loginPassword').value;
    const btn = document.getElementById('loginSubmitBtn');
    const spinner = document.getElementById('loginSpinner');
    const text = document.getElementById('loginSubmitText');
    btn.disabled = true;
    spinner.style.display = 'inline-block';
    text.style.opacity = '0.6';
    sb.auth.signInWithPassword({ email, password: pass, options: { captchaToken: turnstileToken } })
      .then(({ error }) => {
        if (error) {
          showLoginError(authErrorMessage(error.message));
          recordLoginFailure();
        } else {
          clearLoginLockout();
        }
      })
      .finally(() => {
        spinner.style.display = 'none';
        text.style.opacity = '1';
        applyLoginLockoutUI();
        resetTurnstile();
      });
  });

  document.getElementById('loginForgotBtn').addEventListener('click', function () {
    const email = document.getElementById('loginEmail').value.trim();
    if (!email) {
      showLoginError('Enter your email above first, then click "Forgot password" again.');
      return;
    }
    sb.auth.resetPasswordForEmail(email, { captchaToken: turnstileToken })
      .then(({ error }) => {
        if (error) showLoginError(authErrorMessage(error.message));
        else showLoginError('✅ A reset link was sent to your email.');
      })
      .finally(() => resetTurnstile());
  });

  function employeeLogout() {
    closeProfileMenu();
    stopPresenceHeartbeat();
    stopPresenceAdminRefresh();
    stopUpdatesPolling();
    stopMentorChatPoll();
    stopBreakWatcher();
    stopMentorRequestsPolling();
    sb.auth.signOut().then(({ error }) => {
      if (error) console.error('Supabase signOut error:', error);
      // Force the login gate open immediately — don't rely solely on the
      // onAuthStateChange event, in case it's delayed or doesn't fire.
      document.getElementById('loginGate').classList.remove('hide');
      appBooted = false;
    });
  }

  function toggleProfileMenu() {
    const dd = document.getElementById('profileDropdown');
    const btn = document.getElementById('profileBtn');
    const wasOpen = dd.classList.contains('open');
    const isOpen = dd.classList.toggle('open');
    btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    // Same idea as the side panels: don't leave the hero's background animations
    // competing with this dropdown's own open/close transition for frame budget.
    if (isOpen && !wasOpen) pauseCmdHero();
    else if (!isOpen && wasOpen) resumeCmdHero();
  }
  function closeProfileMenu() {
    const dd = document.getElementById('profileDropdown');
    const wasOpen = dd.classList.contains('open');
    dd.classList.remove('open');
    document.getElementById('profileBtn').setAttribute('aria-expanded', 'false');
    if (wasOpen) resumeCmdHero();
  }
  document.addEventListener('click', function (e) {
    const menu = document.getElementById('profileMenu');
    if (menu && !menu.contains(e.target)) closeProfileMenu();
  });

  function updateProfileIdentity(email) {
    currentUserEmail = email || null;
    const initials = (email || '؟').trim().slice(0, 2).toUpperCase();
    document.getElementById('profileAvatar').textContent = initials;
    document.getElementById('profileAvatarLg').textContent = initials;
    document.getElementById('profileEmail').textContent = email || '—';
    const senderEl = document.getElementById('suggestSenderEmail');
    if (senderEl) senderEl.textContent = email || '—';
  }

  // بيجيب البوزيشن (role) الخاصة بالمستخدم من جدول profiles على Supabase
  async function fetchUserRole(userId) {
    try {
      const { data, error } = await sb
        .from('profiles')
        .select('role')
        .eq('id', userId)
        .single();
      if (error || !data || !data.role) {
        console.warn('تعذّر جلب البوزيشن، تم استخدام الافتراضي:', error?.message);
        return DEFAULT_ROLE;
      }
      return data.role;
    } catch (err) {
      console.error('خطأ أثناء جلب البوزيشن:', err);
      return DEFAULT_ROLE;
    }
  }

  // بيطبّق الصلاحيات على الواجهة حسب البوزيشن (بدون إعادة رسم — الاستدعاء المسؤول يقرر متى يرسم)
  function applyUserRole(role) {
    const perm = ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS[DEFAULT_ROLE];
    currentUserRole = ROLE_PERMISSIONS[role] ? role : DEFAULT_ROLE;
    isAdmin = perm.isAdmin;
    adminRole = perm.adminRole;

    const roleLabelEl = document.getElementById('profileRoleLabel');
    if (roleLabelEl) {
      const isAr = currentLang === 'ar';
      roleLabelEl.textContent = isAr ? perm.label.ar : perm.label.en;
    }

    updateAdminRoleLabel();
  }

  sb.auth.onAuthStateChange(function (event, session) {
    const gate = document.getElementById('loginGate');
    if (session && session.user) {
      gate.classList.add('hide');
      document.getElementById('loginForm').reset();
      hideLoginError();
      destroyTurnstile();
      hasEverLoggedIn = true;
      updateProfileIdentity(session.user.email);
      if (!appBooted) {
        appBooted = true;
        bootApp(session.user.id);
      } else {
        // الجلسة نفسها اتجدد توكنها مثلاً — حدّث البوزيشن بس بدون إعادة تحميل كل شي
        fetchUserRole(session.user.id).then(role => {
          applyUserRole(role);
          render();
          if (isAdmin) renderAdminLists();
        });
      }
    } else {
      gate.classList.remove('hide');
      closeProfileMenu();
      document.getElementById('splashOverlay')?.remove();
      isAdmin = false;
      adminRole = null;
      currentUserRole = null;
      stopPresenceHeartbeat();
      stopPresenceAdminRefresh();
      stopUpdatesPolling();
      stopMentorChatPoll();
      stopBreakWatcher();
      stopMentorRequestsPolling();
      // Only re-render if this is a real sign-out after a real login
      // (hasEverLoggedIn) - the very first page load also fires this branch
      // with no session yet, and at that point the widget either hasn't
      // rendered yet (the CDN script's own onload will do it) or already
      // has, so re-rendering here would either race it or duplicate it.
      if (hasEverLoggedIn && turnstileWidgetId === null) onTurnstileApiLoad();
    }
  });
  // ====== End Supabase Authentication ======

  const DEFAULT_CATEGORIES = [
    { key:'delivery', label:'Delivery & Shipping', labelAr:'التوصيل والشحن', color:'#2563EB' },
    { key:'courier', label:'Courier Complaints', labelAr:'شكاوى المندوب', color:'#DC5F45' },
    { key:'escalation', label:'Escalations', labelAr:'التصعيد والشكاوى', color:'#7C3AED' },
    { key:'order', label:'Order Issues', labelAr:'مشاكل الطلبات', color:'#D69E2E' },
    { key:'account', label:'Account Updates', labelAr:'تحديث البيانات', color:'#0D9488' }
  ];

  const DEFAULT_SCRIPTS = [
    { cat:'delivery', title:'Order Expedite Request', titleAr:'طلب استعجال الطلب', text:'The customer is requesting to expedite their order and needs it as soon as possible.\n\nThank you for your cooperation.', textAr:'يرغب العميل في استعجال الشحنة ويحتاجها في أقرب وقت ممكن.\n\nشاكرين تعاونكم.', usageCount: 0 },
    { cat:'delivery', title:'Redelivery Request', titleAr:'طلب إعادة التوصيل', text:'Kindly arrange redelivery of the shipment.\n\nThank you very much.\nCustomer Service Team', textAr:'يرجى إعادة جدولة توصيل الشحنة للعميل.\n\nشاكرين لكم.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'delivery', title:'Stop Delivery', titleAr:'إيقاف التوصيل', text:'The customer would like to stop the delivery of the shipment.\n\nThank you.\nCustomer Service Team', textAr:'يرغب العميل في إيقاف توصيل الشحنة.\n\nشكراً لكم.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'delivery', title:'Warehouse Pickup Request', titleAr:'طلب استلام من المستودع', text:'The customer would like to pick up the shipment from the warehouse. Please provide the customer with the warehouse location.\n\nThank you.\nCustomer Service Team', textAr:'يرغب العميل في استلام الشحنة مباشرة من المستودع. يرجى تزويد العميل بموقع المستودع.\n\nشكراً لكم.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'courier', title:'Courier Behavior Complaint', titleAr:'شكوى سوء تعامل المندوب', text:'The courier\'s behavior toward the customer was very poor and unprofessional. The customer would like to file a complaint.\n\nPlease take the appropriate action in accordance with company standards.\nCustomer Service Team', textAr:'تعامل المندوب مع العميل كان غير لائق وغير احترافي، والعميل يرغب برفع شكوى رسمية.\n\nيرجى اتخاذ الإجراء المناسب وفق المعايير.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'courier', title:'Courier Unresponsive to Calls', titleAr:'المندوب لا يرد على الاتصالات', text:'The customer has been trying to reach the courier but is not getting any response.\n\nPlease resolve this issue as soon as possible.\nCustomer Service Team', textAr:'يحاول العميل التواصل مع المندوب دون أي استجابة.\n\nيرجى حل المشكلة بأسرع وقت.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'courier', title:'Courier Charged Extra Amount', titleAr:'المندوب طلب مبلغاً إضافياً', text:'The courier collected an additional amount from the customer.\n\nPlease investigate this violation.\nCustomer Service Team', textAr:'قام المندوب بتحصيل مبلغ إضافي غير مستحق من العميل.\n\nيرجى التحقيق في هذه المخالفة.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'courier', title:'Courier Refuses Home Delivery', titleAr:'المندوب يرفض التوصيل للمنزل', text:'The courier is refusing to deliver the shipment to the customer\'s home.\n\nPlease resolve this issue.\nCustomer Service Team', textAr:'يرفض المندوب توصيل الشحنة إلى عنوان منزل العميل.\n\nيرجى معالجة الطلب.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'escalation', title:'TGA Escalation', titleAr:'تصعيد شكوى هيئة النقل (TGA)', text:'The customer wishes to file an official complaint against our company.\n\nPlease reach out to them and address the issue accordingly.\nCustomer Service Team', textAr:'يرغب العميل في تقديم شكوى رسمية ضد الشركة لدى هيئة النقل.\n\nيرجى التواصل معه ومعالجة المشكلة فوراً.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'order', title:'Order Shortage', titleAr:'نقص في محتويات الطلب', text:'The customer received the shipment, but it appears to be missing items.\n\nPlease investigate the incident and respond as soon as possible.\nCustomer Service Team', textAr:'استلم العميل الشحنة وتبين وجود نقص في المنتجات.\n\nيرجى التحقيق والرد بأسرع وقت.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'order', title:'Wrong Shipment', titleAr:'شحنة خاطئة', text:'The customer received the wrong shipment and is upset.\n\nPlease investigate and resolve the issue.\nCustomer Service Team', textAr:'استلم العميل شحنة بالخطأ وهو مستاء جداً.\n\nيرجى التحقيق ومعالجة الخطأ.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'order', title:'Damaged Shipment', titleAr:'شحنة متضررة / تالفة', text:'The shipment is damaged and the customer is upset.\n\nPlease investigate and resolve the issue.\nCustomer Service Team', textAr:'الشحنة تالفة والعميل غاضب.\n\nيرجى متابعة التلف مع القسم المعني.\nفريق خدمة العملاء', usageCount: 0 },
    { cat:'account', title:'Address Update', titleAr:'تعديل عنوان التسليم', text:'Kindly update the customer\'s address.\n\nNew address: [enter new address]', textAr:'يرجى تعديل عنوان العميل إلى العنوان الجديد التالي:\n\nالعنوان الجديد: [أدخل العنوان الجديد]', usageCount: 0 }
  ];

  const DEFAULT_GENERAL_INFO = [
    { label: "أوقات التوصيل / Delivery Hours", val: "من 8:30 صباحاً حتى 9:00 مساءً" },
    { label: "JDL WhatsApp number", val: "15557294873" },
    { label: "خدمة عملاء JDL", val: "966115006100" },
    { label: "خدمة عملاء JDL (مجاني)", val: "9668008852222" },
    { label: "إيميل البروف / Proof Email", val: "JDL_SA@JD.COM" },
    { label: "متى نرفع شكوى ضياع؟", val: "إذا لم يتحدث التتبع لمدة 7 أيام متواصلة" }
  ];

  const DEFAULT_CRITICAL_ITEMS = [
    "Not Correct / Not Complete Information from ALL Systems (معلومات غير صحيحة/غير مكتملة)",
    "Any kind of fake promise (إعطاء وعود وهمية للعميل)",
    "Not asking for the waybill number (عدم طلب رقم البوليسة)",
    "Holding customer > 1 min, or mute > 30 sec (تجاوز الـ Hold دقيقة أو الـ Mute 30 ثانية)"
  ];

  const DEFAULT_ETIQUETTE_ITEMS = [
    "👋 Greeting (الترحيب)", "🙏 Apologize (الاعتذار عند المشكلة)", 
    "✅ Confirm (تأكيد البيانات)", "🔍 Verify (التحقق)", 
    "🤝 Assist (تقديم المساعدة)", "🛠️ Resolve (حل المشكلة)", 
    "🙌 Appreciate (الشكر والتقدير)", "⭐ Evaluation (طلب التقييم)"
  ];

  const DEFAULT_UPDATES = [];
  const DEFAULT_SUGGESTIONS = [];

  const FOLLOWUP = [
    { title:'Any Updates', titleAr:'متابعة التحديثات', text:'Any updates?\n\nCustomer Service Team', textAr:'هل يوجد أي تحديث على هذا الطلب؟\n\nفريق خدمة العملاء', usageCount: 0 },
    { title:'Customer Called Again', titleAr:'معاودة اتصال العميل', text:'The customer has called again.\n\nCustomer Service Team', textAr:'قام العميل بالاتصال مجدداً لمتابعة الطلب.\n\nفريق خدمة العملاء', usageCount: 0 }
  ];

  // البيانات هلأ مشتركة بين كل الموظفين عبر Supabase — مش محلية بالمتصفح.
  let CATEGORIES = [];
  let SCRIPTS = [];
  let GENERAL_INFO = [];
  let CRITICAL_ITEMS = [];
  let ETIQUETTE_ITEMS = [];
  let UPDATES = [];
  let SUGGESTIONS = [];
  let SCRIPT_SUBMISSIONS = [];
  let MENTOR_REQUESTS = [];
  let BREAK_SCHEDULE = [];
  let BREAK_SWAP_REQUESTS = [];

  function todayDateStr() {
    const d = new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }

  // يجيب كل بيانات المشروع من Supabase مرة وحدة بعد تسجيل الدخول.
  // كل الاستعلامات هون تنطلق مع بعض بنفس اللحظة (Promise.all واحد بس) بدل
  // ما تنتظر وحدة الثانية بالدور — كانت مقسّمة لأربع مراحل متسلسلة (الجدول
  // الأساسي، ثم الاقتراحات، ثم المساهمات، ثم طلبات الرعاية، ثم بيانات
  // التدريب)، فكان وقت التحميل الكلي = مجموع وقت كل مرحلة بدل أطول مرحلة
  // فيهم بس — وهذا كان يبطّئ كل تسجيل دخول لكل مستخدم.
  async function loadAllData() {
    const [catRes, scrRes, genRes, critRes, etiqRes, updRes, sugRes, subRes, mentReqRes, , breakSchedRes, breakSwapRes] = await Promise.all([
      sb.from('categories').select('*').order('created_at', { ascending: true }),
      sb.from('scripts').select('*').order('id', { ascending: true }),
      sb.from('general_info').select('*').order('id', { ascending: true }),
      sb.from('critical_items').select('*').order('id', { ascending: true }),
      sb.from('etiquette_items').select('*').order('id', { ascending: true }),
      sb.from('updates').select('*').order('id', { ascending: false }),
      // الاقتراحات: الاستعلام بيصير دايمًا (مش بس للأدمن) — RLS نفسها بترجع صفوف فاضية
      // لغير الأدمن/تيم ليدر، فما في داعي نستنى نعرف الدور قبل ما نطلق الاستعلام.
      // هذا هو اللي كان يجبر bootApp() تنتظر fetchUserRole() كامل قبل ما تبلش
      // loadAllData() أصلاً — يعني رحلة شبكة كاملة زيادة بالتسلسل بكل تسجيل دخول.
      sb.from('suggestions').select('*').order('id', { ascending: false }),
      // مساهمات السكريبتات: كل موظف يشوف مساهماته هو، والأدمن يشوفهم كلهم (RLS بتحدد هيك تلقائياً)
      sb.from('script_submissions').select('*').order('id', { ascending: false }),
      // طلبات الرعاية/التدريب — كل موظف يشوف بس الطلبات اللي هو طرف فيها (متدرب أو راعي)
      sb.from('mentor_requests').select('*').order('id', { ascending: false }),
      // بيانات مركز التدريب (Dynamic) — يتم تحميلها لكل المستخدمين (RLS بتحدد شو يوصلهم فعلياً)
      loadTrainingData(),
      // جدول البريكات وطلبات السواب: يوم اليوم بس (RLS بتحدد وصول القراءة/الكتابة).
      // يتحمّل هون (مش عند فتح الصفحة بس) عشان مراقب التنبيه الصوتي يقدر يشتغل
      // من لحظة تسجيل الدخول حتى لو الموظف ما فتح صفحة البريكات أصلاً.
      sb.from('break_schedule').select('*').eq('work_date', todayDateStr()),
      sb.from('break_swap_requests').select('*').eq('work_date', todayDateStr()).order('id', { ascending: false })
    ]);

    CATEGORIES = catRes.error ? DEFAULT_CATEGORIES : (catRes.data || []).map(c => ({ key: c.key, label: c.label, labelAr: c.label_ar, color: c.color }));
    SCRIPTS = scrRes.error ? DEFAULT_SCRIPTS : (scrRes.data || []).map(s => ({ id: s.id, cat: s.cat, title: s.title, titleAr: s.title_ar, text: s.text, textAr: s.text_ar, usageCount: s.usage_count || 0 }));
    GENERAL_INFO = genRes.error ? DEFAULT_GENERAL_INFO : (genRes.data || []).map(g => ({ id: g.id, label: g.label, labelAr: g.label_ar, val: g.val, valAr: g.val_ar }));
    CRITICAL_ITEMS = critRes.error ? DEFAULT_CRITICAL_ITEMS.map(t => ({ text: t })) : (critRes.data || []).map(c => ({ id: c.id, text: c.text, textAr: c.text_ar }));
    ETIQUETTE_ITEMS = etiqRes.error ? DEFAULT_ETIQUETTE_ITEMS.map(t => ({ text: t })) : (etiqRes.data || []).map(e => ({ id: e.id, text: e.text, textAr: e.text_ar }));
    UPDATES = updRes.error ? [] : (updRes.data || []).map(u => ({ id: u.id, text: u.text, imageUrl: u.image_url, createdAt: new Date(u.created_at).getTime() }));
    SUGGESTIONS = sugRes.error ? [] : (sugRes.data || []).map(s => ({ id: s.id, name: s.name, text: s.text, createdAt: new Date(s.created_at).getTime() }));
    SCRIPT_SUBMISSIONS = subRes.error ? [] : (subRes.data || []).map(s => ({
      id: s.id, cat: s.cat, title: s.title, titleAr: s.title_ar, text: s.text, textAr: s.text_ar,
      submittedBy: s.submitted_by, status: s.status, createdAt: new Date(s.created_at).getTime()
    }));
    MENTOR_REQUESTS = mentReqRes.error ? [] : (mentReqRes.data || []).map(r => ({
      id: r.id, traineeEmail: r.trainee_email, mentorEmail: r.mentor_email, note: r.note,
      status: r.status, createdAt: new Date(r.created_at).getTime()
    }));
    BREAK_SCHEDULE = breakSchedRes.error ? [] : (breakSchedRes.data || []).map(r => ({
      id: r.id, employeeEmail: r.employee_email, workDate: r.work_date,
      break1: r.break1_time, break2: r.break2_time, break3: r.break3_time
    }));
    BREAK_SWAP_REQUESTS = breakSwapRes.error ? [] : (breakSwapRes.data || []).map(r => ({
      id: r.id, workDate: r.work_date,
      requesterEmail: r.requester_email, requesterSlot: r.requester_break_slot,
      targetEmail: r.target_email, targetSlot: r.target_break_slot,
      status: r.status, createdAt: r.created_at
    }));
  }

  // ===================== Online Users (Presence) =====================
  // نظام تتبّع حالة الاتصال. كل مستخدم مسجّل دخول يبعث "نبضة" (heartbeat) دورية
  // لجدول user_presence على Supabase؛ الأدمن يشوف قائمة بكل المستخدمين وحالتهم
  // (متصل/غير متصل) بالاعتماد على آخر نبضة وصلت، مع تحديث دوري تلقائي بدون Reload.
  // ملاحظة: هاد النظام منفصل تماماً عن تسجيل الدخول (Supabase Auth) ولا يغيّر فيه شي.
  const PRESENCE_HEARTBEAT_MS = 20000;       // كل كم ثانية نبعث نبضة "أنا لسا موجود"
  const PRESENCE_ONLINE_THRESHOLD_MS = 45000; // إذا آخر نبضة أقدم من هيك، يعتبر Offline
  const PRESENCE_ADMIN_REFRESH_MS = 8000;     // كل كم ثانية تتحدث القائمة عند الأدمن

  let presenceHeartbeatTimer = null;
  let presenceAdminRefreshTimer = null;
  let PRESENCE_USERS = [];
  let currentSessionStartedAt = null;

  async function upsertPresence(isNewSession) {
    if (!currentUserEmail) return;
    try {
      // sb.auth.getUser() (unlike getSession()) verifies the token against
      // the Supabase server on every call instead of just reading the local
      // cached one — so this heartbeat, already running every 20s, is also
      // what detects an account an admin just deleted and signs it out right
      // here, in this same tab, with no page refresh needed. A locally-valid
      // but server-rejected token comes back as an error here.
      const { data, error: userErr } = await sb.auth.getUser();
      if (userErr) {
        stopPresenceHeartbeat();
        await sb.auth.signOut();
        return;
      }
      const user = data && data.user;
      const uid = user && user.id;
      if (!uid) return;
      checkSystemLock();
      const isFreshLogin = isNewSession || !currentSessionStartedAt;
      if (isFreshLogin) currentSessionStartedAt = new Date().toISOString();
      const { data: presRow, error } = await sb.from('user_presence').upsert({
        user_id: uid,
        email: currentUserEmail,
        session_started_at: currentSessionStartedAt,
        last_seen: new Date().toISOString()
      }, { onConflict: 'user_id' }).select('force_logout_at').single();
      if (error) console.warn('تعذّر تحديث حالة الاتصال (presence):', error.message);
      // An admin can force-logout a specific person from the Online Users list
      // (stamps this same row's force_logout_at). If that stamp is newer than
      // when THIS session started, it targets us — sign out right here, no
      // refresh needed. A fresh login always sets a later session_started_at,
      // so this naturally stops matching after logging back in - nothing to
      // reset. Skipped on the very login that just set currentSessionStartedAt,
      // since a stale stamp from a previous session shouldn't kill the new one.
      if (!isFreshLogin && presRow && presRow.force_logout_at &&
          new Date(presRow.force_logout_at) > new Date(currentSessionStartedAt)) {
        stopPresenceHeartbeat();
        await sb.auth.signOut();
      }
    } catch (err) {
      console.warn('presence heartbeat error:', err);
    }
  }

  // ===================== Temporary shutdown / maintenance mode =====================
  // Piggybacks on the presence heartbeat above (already a live round trip to
  // the server every ~20s) instead of running its own timer, so a full admin
  // flipping the switch reaches every other open tab within one heartbeat —
  // no page refresh needed, same mechanism as the deleted-user sign-out.
  async function checkSystemLock() {
    try {
      const { data, error } = await sb.from('system_lock').select('locked, message, message_ar').eq('id', 1).single();
      const overlay = document.getElementById('maintenanceOverlay');
      if (error || !data || !overlay) return;
      const shouldBlock = !!data.locked && adminRole !== 'full';
      overlay.classList.toggle('show', shouldBlock);
      if (shouldBlock) {
        const isAr = currentLang === 'ar';
        const fallback = isAr
          ? 'جاري العمل على تحديث أو صيانة سريعة — رح يرجع الموقع خلال شوي.'
          : 'A quick maintenance/update is in progress — the site will be back shortly.';
        document.getElementById('maintenanceMsg').textContent = (isAr ? data.message_ar : data.message) || fallback;
      }
    } catch (err) {
      console.warn('تعذّر التحقق من حالة الإيقاف المؤقت:', err);
    }
  }

  async function loadLockTabState() {
    const statusLine = document.getElementById('lockStatusLine');
    const { data, error } = await sb.from('system_lock').select('locked, message, message_ar').eq('id', 1).single();
    if (error || !data) {
      if (statusLine) statusLine.textContent = 'تعذّر تحميل الحالة الحالية.';
      return;
    }
    document.getElementById('lockToggle').checked = !!data.locked;
    document.getElementById('lockMessage').value = data.message_ar || data.message || '';
    if (statusLine) statusLine.textContent = data.locked ? '🔴 الموقع متوقف حاليًا لكل الموظفين.' : '🟢 الموقع شغال بشكل طبيعي.';
  }

  async function saveLockState() {
    const locked = document.getElementById('lockToggle').checked;
    const message = document.getElementById('lockMessage').value.trim();
    const isAr = currentLang === 'ar';
    const { error } = await sb.from('system_lock').update({
      locked, message: message || null, message_ar: message || null,
      updated_by: currentUserEmail, updated_at: new Date().toISOString()
    }).eq('id', 1);
    if (error) {
      showToast(isAr ? 'تعذّر الحفظ.' : 'Could not save.', 'error');
      return;
    }
    showToast(
      locked ? (isAr ? 'تم إيقاف الموقع مؤقتًا.' : 'The site is now paused.') : (isAr ? 'تم تشغيل الموقع.' : 'The site is back on.'),
      'success'
    );
    loadLockTabState();
    checkSystemLock();
  }

  // Read-only view onto the database-level audit_log table (see
  // supabase_audit_log.sql) — this app never writes to that table itself,
  // triggers do, so this is purely for a full admin to review it.
  async function loadAuditLog() {
    const list = document.getElementById('auditLogList');
    if (!list) return;
    const isAr = currentLang === 'ar';
    list.innerHTML = `<div style="font-size:11.5px; color:var(--slate-soft);">${isAr ? 'جاري التحميل...' : 'Loading...'}</div>`;
    const { data, error } = await sb.from('audit_log').select('*').order('id', { ascending: false }).limit(200);
    if (error) {
      list.innerHTML = `<div style="font-size:11.5px; color:var(--slate-soft);">${isAr ? 'تعذّر تحميل السجل.' : 'Could not load the log.'}</div>`;
      return;
    }
    renderAuditLog(data || []);
  }

  function renderAuditLog(rows) {
    const list = document.getElementById('auditLogList');
    const isAr = currentLang === 'ar';
    if (!list) return;
    if (!rows.length) {
      list.innerHTML = `<div style="font-size:11.5px; color:var(--slate-soft);">${isAr ? 'لا يوجد أي سجل بعد.' : 'No entries yet.'}</div>`;
      return;
    }
    const actionColor = { INSERT: '#10B981', UPDATE: '#D97706', DELETE: '#B91C1C' };
    const actionLabel = isAr
      ? { INSERT: 'إضافة', UPDATE: 'تعديل', DELETE: 'حذف' }
      : { INSERT: 'Insert', UPDATE: 'Update', DELETE: 'Delete' };
    list.innerHTML = rows.map(r => {
      const color = actionColor[r.action] || '#64748B';
      const label = actionLabel[r.action] || r.action;
      const dateStr = new Date(r.created_at).toLocaleString(isAr ? 'ar-EG' : 'en-US', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
      const summary = summarizeAuditDetails(r.details);
      return `<div style="border-bottom:1px solid var(--border); padding:7px 0; font-size:11.5px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
          <span><span style="font-weight:800; color:${color}; background:color-mix(in srgb, ${color} 14%, transparent); padding:2px 8px; border-radius:999px; font-size:10px;">${escapeHtml(label)}</span>
            <span style="font-weight:700; margin-inline-start:6px;">${escapeHtml(r.target_table)}</span>${r.target_id ? ` <span style="color:var(--slate-soft); font-family:'JetBrains Mono', monospace; font-size:10px;">#${escapeHtml(r.target_id)}</span>` : ''}</span>
          <span style="color:var(--slate-soft); font-size:10px; flex-shrink:0;">${dateStr}</span>
        </div>
        <div style="color:var(--slate-soft); margin-top:2px;">${escapeHtml(r.actor_email || (isAr ? 'غير معروف' : 'unknown'))}${summary ? ' — ' + escapeHtml(summary) : ''}</div>
      </div>`;
    }).join('');
  }

  // Best-effort one-line summary of a details payload for the audit list —
  // not every table has the same shape, so try the common text-ish fields.
  function summarizeAuditDetails(details) {
    if (!details || typeof details !== 'object') return '';
    const candidates = ['title', 'title_ar', 'label', 'label_ar', 'text', 'text_ar', 'phone_number', 'role', 'locked', 'force_logout_at'];
    for (const key of candidates) {
      if (details[key] !== undefined && details[key] !== null && details[key] !== '') {
        return String(details[key]).slice(0, 80);
      }
    }
    return '';
  }

  function startPresenceHeartbeat() {
    stopPresenceHeartbeat();
    upsertPresence(true);
    presenceHeartbeatTimer = setInterval(() => upsertPresence(false), PRESENCE_HEARTBEAT_MS);
    // آخر محاولة "أفضل جهد" لتحديث آخر ظهور لحظة إغلاق التبويب/الصفحة
    window.addEventListener('beforeunload', sendPresenceBeacon);
  }

  function stopPresenceHeartbeat() {
    if (presenceHeartbeatTimer) { clearInterval(presenceHeartbeatTimer); presenceHeartbeatTimer = null; }
    currentSessionStartedAt = null;
    window.removeEventListener('beforeunload', sendPresenceBeacon);
  }

  // ===================== New-update notification sound =====================
  // A short two-tone "ding", synthesized with the Web Audio API — no audio
  // file to fetch, so it plays instantly and needs no extra CSP allowance.
  function playNotificationSound() {
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = new Ctx();
      const now = ctx.currentTime;
      [880, 1320].forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0, now + i * 0.12);
        gain.gain.linearRampToValueAtTime(0.18, now + i * 0.12 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.12 + 0.22);
        osc.connect(gain).connect(ctx.destination);
        osc.start(now + i * 0.12);
        osc.stop(now + i * 0.12 + 0.25);
      });
      setTimeout(() => ctx.close(), 600);
    } catch (err) { /* audio not available in this browser/context — ignore */ }
  }

  const UPDATES_POLL_MS = 45000;
  let updatesPollTimer = null;
  let lastKnownUpdateId = 0;

  async function pollForNewUpdates() {
    const { data, error } = await sb.from('updates').select('id').order('id', { ascending: false }).limit(1);
    if (error || !data || !data.length) return;
    const latestId = data[0].id;
    if (latestId <= lastKnownUpdateId) return;
    lastKnownUpdateId = latestId;
    const { data: fullData, error: fullError } = await sb.from('updates').select('*').order('id', { ascending: false });
    if (fullError) return;
    UPDATES = (fullData || []).map(u => ({ id: u.id, text: u.text, imageUrl: u.image_url, createdAt: new Date(u.created_at).getTime() }));
    updateNotificationBadge();
    refreshHeroCounts();
    if (document.getElementById('updatesPage').classList.contains('open')) renderUpdatesPage();
    playNotificationSound();
    fireUpdateNotification(UPDATES[0]);
  }
  // An OS-level notification for a brand-new update, so it reaches you even while
  // you're away from the tab — not just the in-page badge/sound, which only helps
  // if you're actually looking at (or listening to) the site right now.
  function fireUpdateNotification(update) {
    if (!update || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
    const isAr = currentLang === 'ar';
    const title = isAr ? '📢 تحديث جديد' : '📢 New update';
    const body = (update.text || '').slice(0, 140);
    try { new Notification(title, { body, icon: '/icons/icon-192.png' }); } catch (e) { /* best-effort only */ }
  }

  function startUpdatesPolling() {
    stopUpdatesPolling();
    lastKnownUpdateId = UPDATES.reduce((max, u) => Math.max(max, u.id), 0);
    updatesPollTimer = setInterval(pollForNewUpdates, UPDATES_POLL_MS);
  }
  function stopUpdatesPolling() {
    if (updatesPollTimer) { clearInterval(updatesPollTimer); updatesPollTimer = null; }
  }

  function sendPresenceBeacon() {
    // Best-effort: matawwar tarslib request عادي بيولي، مش أكيد توصل، لهيك ما نعتمد عليها لوحدها
    upsertPresence(false);
  }

  function startPresenceAdminRefresh() {
    stopPresenceAdminRefresh();
    presenceAdminRefreshTimer = setInterval(loadPresenceUsers, PRESENCE_ADMIN_REFRESH_MS);
  }
  function stopPresenceAdminRefresh() {
    if (presenceAdminRefreshTimer) { clearInterval(presenceAdminRefreshTimer); presenceAdminRefreshTimer = null; }
  }

  async function loadPresenceUsers() {
    if (!isAdmin) return;
    const { data, error } = await sb.from('user_presence').select('*').order('last_seen', { ascending: false });
    if (error) {
      console.warn('تعذّر جلب قائمة المستخدمين المتصلين:', error.message);
      return;
    }
    const now = Date.now();
    PRESENCE_USERS = (data || []).map(r => {
      const lastSeenMs = new Date(r.last_seen).getTime();
      return {
        userId: r.user_id,
        email: r.email,
        sessionStartedAt: r.session_started_at,
        lastSeen: r.last_seen,
        isOnline: (now - lastSeenMs) < PRESENCE_ONLINE_THRESHOLD_MS
      };
    });
    renderPresenceList();
  }

  function relativeTimeAr(ms) {
    const sec = Math.max(0, Math.round(ms / 1000));
    if (sec < 10) return 'الآن';
    if (sec < 60) return `منذ ${sec} ثانية`;
    const min = Math.round(sec / 60);
    if (min < 60) return `منذ ${min} دقيقة`;
    const hr = Math.round(min / 60);
    if (hr < 24) return `منذ ${hr} ساعة`;
    const day = Math.round(hr / 24);
    return `منذ ${day} يوم`;
  }
  function relativeTimeEn(ms) {
    const sec = Math.max(0, Math.round(ms / 1000));
    if (sec < 10) return 'just now';
    if (sec < 60) return `${sec}s ago`;
    const min = Math.round(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.round(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.round(hr / 24);
    return `${day}d ago`;
  }

  async function forceLogoutUser(userId, email) {
    const isAr = currentLang === 'ar';
    const msg = isAr
      ? `تسجيل خروج "${email}" فورًا من كل الأجهزة اللي عندو فاتحها؟`
      : `Sign "${email}" out immediately from every device they have open?`;
    if (!confirm(msg)) return;
    const { error } = await sb.from('user_presence').update({ force_logout_at: new Date().toISOString() }).eq('user_id', userId);
    if (error) {
      showToast(isAr ? 'تعذّر تنفيذ العملية.' : 'Could not complete the action.', 'error');
      return;
    }
    showToast(isAr ? 'تم — رح يطلع خلال ٢٠ ثانية بدون رفرش.' : 'Done — they\'ll be signed out within 20s, no refresh needed.', 'success');
  }

  function renderPresenceList() {
    const isAr = currentLang === 'ar';
    const body = document.getElementById('presenceTableBody');
    const empty = document.getElementById('presenceEmpty');
    const onlineCountEl = document.getElementById('presenceOnlineCount');
    const totalCountEl = document.getElementById('presenceTotalCount');
    if (!body) return;

    const now = Date.now();
    const onlineCount = PRESENCE_USERS.filter(u => u.isOnline).length;
    if (onlineCountEl) onlineCountEl.textContent = onlineCount;
    if (totalCountEl) totalCountEl.textContent = PRESENCE_USERS.length;

    if (!PRESENCE_USERS.length) {
      body.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';

    const timeFn = isAr ? relativeTimeAr : relativeTimeEn;
    const loginTimeFmt = (iso) => iso ? new Date(iso).toLocaleString(isAr ? 'ar-EG' : 'en-US', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';

    const iconLogout = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8"></path><path d="M18 15l4-3-4-3"></path><path d="M22 12H10"></path></svg>`;
    const canForceLogout = adminRole === 'full';

    body.innerHTML = PRESENCE_USERS.map(u => {
      const statusText = u.isOnline ? (isAr ? 'متصل' : 'Online') : (isAr ? 'غير متصل' : 'Offline');
      const lastActiveText = timeFn(now - new Date(u.lastSeen).getTime());
      const loginTimeText = u.isOnline ? loginTimeFmt(u.sessionStartedAt) : '—';
      const initials = (u.email || '؟').trim().slice(0, 2).toUpperCase();
      const isSelf = u.email && currentUserEmail && u.email.toLowerCase() === currentUserEmail.toLowerCase();
      const actionCell = (canForceLogout && !isSelf)
        ? `<button class="presence-logout-btn" data-force-logout="${escapeHtml(u.userId)}" data-force-logout-email="${escapeHtml(u.email || '')}" title="${isAr ? 'تسجيل خروج فوري' : 'Force logout'}" aria-label="${isAr ? 'تسجيل خروج فوري' : 'Force logout'}">${iconLogout}</button>`
        : '';
      return `<tr>
        <td><span class="presence-dot ${u.isOnline ? 'on' : 'off'}" title="${escapeHtml(statusText)}"></span></td>
        <td><span class="presence-user" title="${escapeHtml(u.email || '')}">${escapeHtml(u.email || initials)}</span></td>
        <td><span class="presence-status-pill ${u.isOnline ? 'on' : 'off'}">${statusText}</span></td>
        <td class="presence-time">${lastActiveText}</td>
        <td class="presence-time">${loginTimeText}</td>
        <td>${actionCell}</td>
      </tr>`;
    }).join('');

    body.querySelectorAll('[data-force-logout]').forEach(btn => {
      btn.addEventListener('click', () => forceLogoutUser(btn.dataset.forceLogout, btn.dataset.forceLogoutEmail));
    });
  }
  // ===================== End Online Users (Presence) =====================

  // ===================== Break Schedule (جدول البريكات) =====================
  // بديل الصورة اليومية اللي كانت تُبعث على تيمز — جدول حي: كل موظف وبريكاته الثلاث،
  // مع إمكانية طلب سواب بريك مع زميل (بموافقة الطرفين)، وتنبيه صوتي وقت البريك.
  const BREAK_AVATAR_COLORS = ['#C2410C', '#B91C1C', '#0B84FF', '#7C3AED', '#A16207', '#BE185D', '#0D9488', '#4338CA'];
  function breakAvatarColor(email) {
    let hash = 0;
    const s = email || '';
    for (let i = 0; i < s.length; i++) hash = (hash * 31 + s.charCodeAt(i)) >>> 0;
    return BREAK_AVATAR_COLORS[hash % BREAK_AVATAR_COLORS.length];
  }
  function breakInitials(email) {
    return ((email || '؟').split('@')[0] || '؟').slice(0, 2).toUpperCase();
  }
  function breakDisplayName(email) {
    return (email || '').split('@')[0] || email || '—';
  }
  // t is 'HH:MM' or 'HH:MM:SS' from Postgres time, or null/empty.
  function formatBreakTime(t) {
    if (!t) return null;
    const [hStr, mStr] = t.split(':');
    const h = parseInt(hStr, 10);
    const isAr = currentLang === 'ar';
    const period = h >= 12 ? (isAr ? 'م' : 'PM') : (isAr ? 'ص' : 'AM');
    let h12 = h % 12; if (h12 === 0) h12 = 12;
    return `${h12}:${mStr} ${period}`;
  }
  function myBreakRow() {
    return BREAK_SCHEDULE.find(r => r.employeeEmail === currentUserEmail);
  }

  function openBreaksPage() {
    closePanels();
    closeScriptsPage();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTechPage();
    closeTrainingPage();
    document.getElementById('breaksPage').classList.add('open');
    pauseAllOrbits();
    pauseCmdHero();
    Promise.all([loadDirectoryEmails(), reloadBreakData()]).then(() => {
      renderBreaksPage();
      startBreaksPagePoll();
    });
  }
  function closeBreaksPage() {
    const el = document.getElementById('breaksPage');
    if (!el.classList.contains('open')) return;
    el.classList.remove('open');
    orbitControllers.orbitCanvasHome.start();
    resumeCmdHero();
    stopBreaksPagePoll();
  }

  // ----- Keeps the schedule live while the page is open, so an admin's edit (a
  // retimed slot, a swap, an added/removed employee) shows up for everyone else
  // already looking at it instead of requiring a manual refresh. Same polling
  // approach used for mentor_requests and the break-time watcher — a plain
  // re-select on an interval, diffed so an unchanged poll doesn't re-render and
  // reset the admin's Edit-mode selection or scroll position. -----
  const BREAKS_PAGE_POLL_MS = 15000;
  let breaksPagePollTimer = null;
  let breaksPageLastSignature = null;
  function startBreaksPagePoll() {
    stopBreaksPagePoll();
    breaksPageLastSignature = JSON.stringify(BREAK_SCHEDULE) + '|' + JSON.stringify(BREAK_SWAP_REQUESTS);
    breaksPagePollTimer = setInterval(pollBreaksPageData, BREAKS_PAGE_POLL_MS);
  }
  function stopBreaksPagePoll() {
    if (breaksPagePollTimer) { clearInterval(breaksPagePollTimer); breaksPagePollTimer = null; }
  }
  async function pollBreaksPageData() {
    // Never clobber a time chip the admin is mid-edit on - the fetch still
    // happens so the very next tick (once they commit or blur away) picks up
    // the latest data immediately instead of waiting a full poll cycle behind.
    if (document.querySelector('.breaks-chip.editing')) return;
    await reloadBreakData();
    const signature = JSON.stringify(BREAK_SCHEDULE) + '|' + JSON.stringify(BREAK_SWAP_REQUESTS);
    if (signature === breaksPageLastSignature) return;
    breaksPageLastSignature = signature;
    renderBreaksPage();
  }

  async function reloadBreakData() {
    const today = todayDateStr();
    const [schedRes, swapRes] = await Promise.all([
      sb.from('break_schedule').select('*').eq('work_date', today),
      sb.from('break_swap_requests').select('*').eq('work_date', today).order('id', { ascending: false })
    ]);
    if (!schedRes.error) {
      BREAK_SCHEDULE = (schedRes.data || []).map(r => ({
        id: r.id, employeeEmail: r.employee_email, workDate: r.work_date,
        break1: r.break1_time, break2: r.break2_time, break3: r.break3_time
      }));
    }
    if (!swapRes.error) {
      BREAK_SWAP_REQUESTS = (swapRes.data || []).map(r => ({
        id: r.id, workDate: r.work_date,
        requesterEmail: r.requester_email, requesterSlot: r.requester_break_slot,
        targetEmail: r.target_email, targetSlot: r.target_break_slot,
        status: r.status, createdAt: r.created_at
      }));
    }
  }

  function renderBreaksPage() {
    const isAr = currentLang === 'ar';
    const eyebrow = document.getElementById('breaksEyebrow');
    if (eyebrow) {
      const dateStr = new Date().toLocaleDateString(isAr ? 'ar-EG' : 'en-US', { weekday: 'long', day: 'numeric', month: 'long' });
      eyebrow.textContent = (isAr ? 'جدول اليوم — ' : "Today's schedule — ") + dateStr;
    }

    const editToggleBtn = document.getElementById('breaksEditToggle');
    if (editToggleBtn) editToggleBtn.style.display = isAdmin ? 'inline-flex' : 'none';
    if (!isAdmin && breaksEditMode) { breaksEditMode = false; breaksPickedSeatId = null; }

    const addPanel = document.getElementById('breaksAddPanel');
    if (addPanel) {
      addPanel.style.display = isAdmin ? 'block' : 'none';
      if (isAdmin) {
        const listedEmails = new Set(BREAK_SCHEDULE.map(r => r.employeeEmail));
        const available = DIRECTORY_EMAILS.filter(e => !listedEmails.has(e));
        breaksSelectedToAdd = new Set([...breaksSelectedToAdd].filter(e => available.includes(e)));
        const chips = document.getElementById('breaksAddChips');
        chips.innerHTML = available.map(e =>
          `<span class="chip${breaksSelectedToAdd.has(e) ? ' on' : ''}" data-add-email="${escapeHtml(e)}">${escapeHtml(breakDisplayName(e))}</span>`
        ).join('') || `<span style="font-size:11.5px; color:var(--slate-soft);">${isAr ? 'كل الموظفين مضافين للجدول.' : 'Everyone is already on the schedule.'}</span>`;
        const btn = document.getElementById('breaksAddSelectedBtn');
        btn.disabled = breaksSelectedToAdd.size === 0;
        btn.textContent = breaksSelectedToAdd.size
          ? (isAr ? `+ إضافة ${breaksSelectedToAdd.size} للجدول` : `+ Add ${breaksSelectedToAdd.size} to schedule`)
          : (isAr ? '+ إضافة المحددين للجدول' : '+ Add selected to schedule');
      }
    }

    // Sorted by seat id (creation order), never by name/email — a seat's position on
    // screen must stay put when its occupant changes, or a swap would look like the
    // times themselves moved.
    const rows = [...BREAK_SCHEDULE].sort((a, b) => a.id - b.id);
    const countEl = document.getElementById('breaksEmployeeCount');
    if (countEl) countEl.textContent = rows.length;

    const swapIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 21l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>`;
    const removeIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 7h14"></path><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"></path><path d="M7 7l1 12.5A2 2 0 0 0 10 21h4a2 2 0 0 0 2-1.5L17 7"></path></svg>`;
    const pencilIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>`;
    const breakChipIcons = { 1: '☕', 2: '🍽️', 3: '🎧' };
    const breakChipLabels = { 1: isAr ? 'قهوة' : 'Coffee', 2: isAr ? 'أكل' : 'Meal', 3: isAr ? 'سماعة' : 'Headset' };

    // ----- Stats strip: real numbers derived from today's schedule, not
    // decorative placeholders - first/last break across all three slots, and
    // a genuine conflict count (two employees sharing the exact same slot +
    // time, which the auto-suggest logic is designed to prevent but a manual
    // edit could still create). -----
    const statsRow = document.getElementById('breaksStatsRow');
    if (statsRow) {
      const allTimes = [];
      const seenBySlot = { 1: new Map(), 2: new Map(), 3: new Map() };
      let conflicts = 0;
      rows.forEach(r => {
        [1, 2, 3].forEach(slot => {
          const raw = r['break' + slot];
          if (!raw) return;
          allTimes.push(raw);
          const bucket = seenBySlot[slot];
          if (bucket.has(raw)) conflicts++;
          bucket.set(raw, (bucket.get(raw) || 0) + 1);
        });
      });
      allTimes.sort();
      const first = allTimes.length ? formatBreakTime(allTimes[0]) : '—';
      const last = allTimes.length ? formatBreakTime(allTimes[allTimes.length - 1]) : '—';
      const stat = (value, label) => `<div class="breaks-stat"><div class="v">${escapeHtml(value)}</div><div class="l">${escapeHtml(label)}</div></div>`;
      statsRow.innerHTML = [
        stat(String(rows.length), isAr ? 'موظفين اليوم' : 'On schedule today'),
        stat(first, isAr ? 'أول بريك' : 'First break'),
        stat(last, isAr ? 'آخر بريك' : 'Last break'),
        stat(String(conflicts), isAr ? 'تعارض بالمواعيد' : 'Time conflicts'),
      ].join('');
    }

    const roster = document.getElementById('breaksTableBody');
    if (roster) {
      roster.classList.toggle('edit-mode', breaksEditMode);
      roster.innerHTML = rows.map((r, idx) => {
        const isMe = r.employeeEmail === currentUserEmail;
        const picked = breaksEditMode && r.id === breaksPickedSeatId;
        const hasAnyTime = [1, 2, 3].some(slot => !!r['break' + slot]);
        const chips = [1, 2, 3].map(slot => {
          const raw = r['break' + slot];
          const formatted = formatBreakTime(raw);
          const editBtn = isAdmin
            ? `<button type="button" class="breaks-time-edit-btn" data-edit-row="${r.id}" data-edit-slot="${slot}" title="${isAr ? 'تعديل الوقت يدويًا' : 'Edit time manually'}">${pencilIcon}</button>`
            : '';
          return `<span class="breaks-chip b${slot}"><span class="k"><span class="ic">${breakChipIcons[slot]}</span>${breakChipLabels[slot]}</span><span class="t">${formatted ? escapeHtml(formatted) : '—'}</span>${editBtn}</span>`;
        }).join('');
        const swapBtn = (isMe && hasAnyTime)
          ? `<button type="button" class="breaks-swap-request-btn" data-swap-row="${r.id}" title="${isAr ? 'طلب سواب' : 'Request swap'}">${swapIcon}</button>`
          : '';
        const removeBtn = isAdmin
          ? `<button type="button" class="breaks-remove-btn" data-remove-email="${escapeHtml(r.employeeEmail)}" title="${isAr ? 'إزالة من الجدول' : 'Remove from schedule'}">${removeIcon}</button>`
          : '';
        return `<div class="breaks-row${isMe ? ' me' : ''}${picked ? ' picked' : ''}" data-row-id="${r.id}">
          <div class="breaks-card-top">
            <span class="breaks-identity">
              <span class="breaks-avatar" style="background:${breakAvatarColor(r.employeeEmail)}">${escapeHtml(breakInitials(r.employeeEmail))}</span>
              <span class="breaks-who">
                <span class="breaks-name">${escapeHtml(breakDisplayName(r.employeeEmail))}${isMe ? `<span class="breaks-you-tag">${isAr ? 'هذا صفك' : 'This is you'}</span>` : ''}</span>
                <span class="breaks-seat">${isAr ? 'مقعد' : 'Seat'} ${idx + 1}</span>
              </span>
            </span>
            <span class="breaks-row-actions">${swapBtn}${removeBtn}</span>
          </div>
          <span class="breaks-chips">${chips}</span>
        </div>`;
      }).join('');
    }

    // Incoming: requests targeting me, still pending.
    const incoming = BREAK_SWAP_REQUESTS.filter(r => r.targetEmail === currentUserEmail && r.status === 'pending');
    const incomingCard = document.getElementById('breaksIncomingCard');
    const incomingList = document.getElementById('breaksIncomingList');
    if (incomingCard && incomingList) {
      incomingCard.style.display = incoming.length ? 'block' : 'none';
      document.getElementById('breaksIncomingCount').textContent = incoming.length;
      incomingList.innerHTML = incoming.map(r => `
        <div class="break-req-row">
          <div class="break-req-info">
            <span class="breaks-avatar" style="background:${breakAvatarColor(r.requesterEmail)}">${escapeHtml(breakInitials(r.requesterEmail))}</span>
            <div class="break-req-detail">
              <b>${escapeHtml(breakDisplayName(r.requesterEmail))}</b> ${isAr ? 'بده يعمل سواب معك' : 'wants to swap with you'}
              <div class="swap-desc">${isAr ? 'بريكه' : 'their'} ${escapeHtml(formatBreakTime(findBreakTime(r.requesterEmail, r.requesterSlot)) || '—')} <span class="arrow">⇄</span> ${isAr ? 'بريكك' : 'your'} ${escapeHtml(formatBreakTime(findBreakTime(r.targetEmail, r.targetSlot)) || '—')}</div>
            </div>
          </div>
          <div class="break-req-actions">
            <button type="button" class="break-accept-btn" data-respond-swap="${r.id}" data-accept="1">${isAr ? '✓ قبول' : '✓ Accept'}</button>
            <button type="button" class="break-decline-btn" data-respond-swap="${r.id}" data-accept="0">${isAr ? '✕ رفض' : '✕ Decline'}</button>
          </div>
        </div>`).join('');
    }

    // Outgoing: requests I sent, still pending.
    const outgoing = BREAK_SWAP_REQUESTS.filter(r => r.requesterEmail === currentUserEmail && r.status === 'pending');
    const outgoingCard = document.getElementById('breaksOutgoingCard');
    const outgoingList = document.getElementById('breaksOutgoingList');
    if (outgoingCard && outgoingList) {
      outgoingCard.style.display = outgoing.length ? 'block' : 'none';
      outgoingList.innerHTML = outgoing.map(r => `
        <div class="break-req-row">
          <div class="break-req-info">
            <span class="breaks-avatar" style="background:${breakAvatarColor(r.targetEmail)}">${escapeHtml(breakInitials(r.targetEmail))}</span>
            <div class="break-req-detail">
              <b>${escapeHtml(breakDisplayName(r.targetEmail))}</b>
              <div class="swap-desc">${isAr ? 'بريكك' : 'your'} ${escapeHtml(formatBreakTime(findBreakTime(r.requesterEmail, r.requesterSlot)) || '—')} <span class="arrow">⇄</span> ${isAr ? 'بريكه' : 'their'} ${escapeHtml(formatBreakTime(findBreakTime(r.targetEmail, r.targetSlot)) || '—')}</div>
            </div>
          </div>
          <span class="break-pending-tag">${isAr ? 'بانتظار الرد' : 'Awaiting response'}</span>
        </div>`).join('');
    }
  }

  function findBreakTime(email, slot) {
    const row = BREAK_SCHEDULE.find(r => r.employeeEmail === email);
    return row ? row['break' + slot] : null;
  }

  // ----- Admin inline edit: click a chip's pencil icon, it turns into a native time input in place -----
  function handleBreakTimeEditClick(btn) {
    const chip = btn.closest('.breaks-chip');
    if (!chip || chip.classList.contains('editing')) return;
    const rowId = parseInt(btn.dataset.editRow, 10);
    const slot = btn.dataset.editSlot;
    const row = BREAK_SCHEDULE.find(r => r.id === rowId);
    if (!row) return;
    const raw = row['break' + slot];
    chip.classList.add('editing');
    const icon = chip.querySelector('.ic').outerHTML;
    chip.innerHTML = icon;
    const input = document.createElement('input');
    input.type = 'time';
    input.value = raw ? raw.slice(0, 5) : '';
    chip.appendChild(input);
    input.focus();
    function commit() {
      const val = input.value;
      chip.classList.remove('editing');
      // A native time input reports '' whenever any of its segments (hour/minute/AM-PM)
      // isn't fully filled in yet — extremely easy to hit by typing and pressing Enter
      // before finishing every segment. Treat that as "no change" and just redraw the
      // existing value instead of wiping it out with an empty save.
      if (!val) { renderBreaksPage(); return; }
      saveBreakTime(row.employeeEmail, slot, val);
    }
    input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') input.blur(); });
    input.addEventListener('blur', commit);
  }

  // ----- Admin/lead "Edit" mode: pick two employees to swap which seat (and therefore
  // which fixed break times) each one holds. The times never move — only the employee_email
  // on the two underlying rows is exchanged, via the swap_break_seats() RPC so it's atomic. -----
  let breaksEditMode = false;
  let breaksPickedSeatId = null;
  function toggleBreaksEditMode() {
    if (!isAdmin) return;
    breaksEditMode = !breaksEditMode;
    breaksPickedSeatId = null;
    const isAr = currentLang === 'ar';
    const btn = document.getElementById('breaksEditToggle');
    const label = document.getElementById('breaksEditToggleLabel');
    const hint = document.getElementById('breaksEditHint');
    if (btn) btn.classList.toggle('active', breaksEditMode);
    if (label) label.textContent = breaksEditMode ? (isAr ? 'تم' : 'Done') : (isAr ? 'تعديل' : 'Edit');
    if (hint) hint.classList.toggle('show', breaksEditMode);
    renderBreaksPage();
  }
  function handleSeatSwapClick(rowId) {
    if (breaksPickedSeatId === null) {
      breaksPickedSeatId = rowId;
      renderBreaksPage();
    } else if (breaksPickedSeatId === rowId) {
      breaksPickedSeatId = null;
      renderBreaksPage();
    } else {
      performSeatSwap(breaksPickedSeatId, rowId);
    }
  }
  async function performSeatSwap(idA, idB) {
    const isAr = currentLang === 'ar';
    const rowA = BREAK_SCHEDULE.find(r => r.id === idA);
    const rowB = BREAK_SCHEDULE.find(r => r.id === idB);
    breaksPickedSeatId = null;
    const { error } = await sb.rpc('swap_break_seats', { row_id_a: idA, row_id_b: idB });
    if (error) { showToast(isAr ? 'تعذّر التبديل.' : 'Could not swap.', 'error'); renderBreaksPage(); return; }
    await reloadBreakData();
    renderBreaksPage();
    if (rowA && rowB) {
      showToast(
        isAr
          ? `تم تبديل ${breakDisplayName(rowA.employeeEmail)} و${breakDisplayName(rowB.employeeEmail)}`
          : `Swapped ${breakDisplayName(rowA.employeeEmail)} and ${breakDisplayName(rowB.employeeEmail)}`,
        'success'
      );
    }
  }

  async function saveBreakTime(email, slot, val) {
    const isAr = currentLang === 'ar';
    const col = 'break' + slot + '_time';
    const { error } = await sb.from('break_schedule')
      .update({ [col]: val, updated_by: currentUserEmail, updated_at: new Date().toISOString() })
      .eq('employee_email', email).eq('work_date', todayDateStr());
    if (error) { showToast(isAr ? 'تعذّر الحفظ.' : 'Could not save.', 'error'); }
    await reloadBreakData();
    renderBreaksPage();
  }

  // Bulk-add: pick everyone on shift today as chips, one click adds all of them to the
  // schedule in a single insert - filling in their actual break times happens right in
  // the grid afterward (click a block, type the time), instead of a slow one-at-a-time
  // dropdown flow.
  let breaksSelectedToAdd = new Set();
  function toggleBreaksAddSelection(email) {
    if (breaksSelectedToAdd.has(email)) breaksSelectedToAdd.delete(email);
    else breaksSelectedToAdd.add(email);
    renderBreaksPage();
  }
  // Auto-distribute suggested break times instead of leaving them blank for the admin to
  // type one at a time: break 1 is a 15-minute slot starting at 1:00 PM, break 2 a
  // 30-minute slot starting at 3:00 PM, break 3 another 15-minute slot starting at 7:00 PM,
  // staggered per employee (round-robin) so the whole team isn't on the same break at once.
  // Still just a starting point — any block stays editable.
  // Each slot's stagger step must match its own duration, or consecutive employees'
  // breaks overlap into each other. Each slot's start is a fixed clock time (not chained
  // off the previous slot's end) so the schedule reads as clean round numbers, with a
  // built-in buffer before it so the last employee's previous break is always well
  // finished by the time the next slot begins.
  // With zero overlap ever allowed within a slot, the round-robin caps at 7 employees
  // (15/30/15-minute slots each covering exactly 7 people) before an auto-suggested time
  // would have to repeat. count is shared across all three slots so that cap is consistent
  // everywhere.
  const BREAK_ROTATION_COUNT = 7;
  const BREAK_AUTO_WINDOWS = {
    1: { startMin: 13 * 60, stepMin: 15, count: BREAK_ROTATION_COUNT }, // 1:00 PM
    2: { startMin: 15 * 60, stepMin: 30, count: BREAK_ROTATION_COUNT }, // 3:00 PM
    3: { startMin: 19 * 60, stepMin: 15, count: BREAK_ROTATION_COUNT }, // 7:00 PM
  };
  function computeAutoBreakTime(index, slotNum) {
    const w = BREAK_AUTO_WINDOWS[slotNum];
    const totalMin = w.startMin + (index % w.count) * w.stepMin;
    return String(Math.floor(totalMin / 60)).padStart(2, '0') + ':' + String(totalMin % 60).padStart(2, '0');
  }

  async function addSelectedBreaksEmployees() {
    const emails = [...breaksSelectedToAdd];
    if (!emails.length) return;
    const isAr = currentLang === 'ar';
    const today = todayDateStr();
    const baseIndex = BREAK_SCHEDULE.length; // keep rotating past whoever's already on today's schedule
    const { error } = await sb.from('break_schedule').insert(
      emails.map((email, i) => ({
        employee_email: email, work_date: today, updated_by: currentUserEmail,
        break1_time: computeAutoBreakTime(baseIndex + i, 1),
        break2_time: computeAutoBreakTime(baseIndex + i, 2),
        break3_time: computeAutoBreakTime(baseIndex + i, 3),
      }))
    );
    if (error) { showToast(isAr ? 'تعذّر الإضافة.' : 'Could not add.', 'error'); return; }
    breaksSelectedToAdd = new Set();
    showToast(
      isAr ? `تمت إضافة ${emails.length} موظف مع أوقات بريكات مقترحة — عدّل أي وقت من الجدول إذا حبيت.` : `Added ${emails.length} employee(s) with suggested break times — edit any time in the grid if you'd like.`,
      'success'
    );
    await reloadBreakData();
    renderBreaksPage();
  }

  async function removeBreaksEmployee(email) {
    const isAr = currentLang === 'ar';
    if (!confirm(isAr ? `إزالة ${breakDisplayName(email)} من جدول اليوم؟` : `Remove ${breakDisplayName(email)} from today's schedule?`)) return;
    const { error } = await sb.from('break_schedule').delete()
      .eq('employee_email', email).eq('work_date', todayDateStr());
    if (error) { showToast(isAr ? 'تعذّر الإزالة.' : 'Could not remove.', 'error'); return; }
    await reloadBreakData();
    renderBreaksPage();
  }

  // ----- Swap request flow -----
  let breakSwapRequesterSlot = null;
  function openBreakSwapPicker() {
    const isAr = currentLang === 'ar';
    const myRow = myBreakRow();
    const mySlots = myRow ? [1, 2, 3].filter(s => myRow['break' + s]) : [];
    if (!mySlots.length) return;
    const mySlotSel = document.getElementById('breakSwapMySlot');
    mySlotSel.innerHTML = mySlots.map(s =>
      `<option value="${s}">${isAr ? 'بريك' : 'Break'} ${s} — ${escapeHtml(formatBreakTime(myRow['break' + s]))}</option>`
    ).join('');
    breakSwapRequesterSlot = mySlots[0];
    mySlotSel.value = String(mySlots[0]);
    mySlotSel.onchange = () => { breakSwapRequesterSlot = parseInt(mySlotSel.value, 10); };

    document.getElementById('breakSwapSub').textContent = isAr
      ? 'اختار بريكك، وبعدين مين وأي بريك من بريكاته بدك تاخذه'
      : 'Pick your break, then who and which of their breaks you want';
    const colSel = document.getElementById('breakSwapColleague');
    const others = BREAK_SCHEDULE.filter(r => r.employeeEmail !== currentUserEmail);
    colSel.innerHTML = others.map(r => `<option value="${escapeHtml(r.employeeEmail)}">${escapeHtml(breakDisplayName(r.employeeEmail))}</option>`).join('');
    function populateTargetSlots() {
      const target = others.find(r => r.employeeEmail === colSel.value);
      const slotSel = document.getElementById('breakSwapTargetSlot');
      if (!target) { slotSel.innerHTML = ''; return; }
      slotSel.innerHTML = [1, 2, 3].filter(s => target['break' + s]).map(s =>
        `<option value="${s}">${isAr ? 'بريك' : 'Break'} ${s} — ${escapeHtml(formatBreakTime(target['break' + s]))}</option>`
      ).join('');
    }
    colSel.onchange = populateTargetSlots;
    populateTargetSlots();
    document.getElementById('breakSwapOverlay').classList.add('show');
  }
  function closeBreakSwapPicker() {
    document.getElementById('breakSwapOverlay').classList.remove('show');
  }
  async function sendBreakSwapRequest() {
    const isAr = currentLang === 'ar';
    const targetEmail = document.getElementById('breakSwapColleague').value;
    const targetSlot = document.getElementById('breakSwapTargetSlot').value;
    if (!targetEmail || !targetSlot || !breakSwapRequesterSlot) return;
    const { error } = await sb.from('break_swap_requests').insert({
      work_date: todayDateStr(), requester_email: currentUserEmail, requester_break_slot: breakSwapRequesterSlot,
      target_email: targetEmail, target_break_slot: parseInt(targetSlot, 10)
    });
    closeBreakSwapPicker();
    if (error) { showToast(isAr ? 'تعذّر إرسال الطلب.' : 'Could not send the request.', 'error'); return; }
    showToast(isAr ? 'تم إرسال طلب السواب!' : 'Swap request sent!', 'success');
    await reloadBreakData();
    renderBreaksPage();
  }
  async function respondBreakSwap(requestId, accept) {
    const isAr = currentLang === 'ar';
    const { error } = await sb.rpc('respond_break_swap', { request_id: requestId, accept });
    if (error) { showToast(isAr ? 'تعذّر تنفيذ الإجراء.' : 'Could not complete the action.', 'error'); return; }
    showToast(accept ? (isAr ? 'تم القبول والتبديل!' : 'Accepted and swapped!') : (isAr ? 'تم الرفض.' : 'Declined.'), 'success');
    await reloadBreakData();
    renderBreaksPage();
  }

  // ----- Break-time notification watcher (with sound), runs from login regardless of
  // whether the Breaks page is ever opened. Re-checks against the server every tick
  // instead of relying on the schedule loaded at login, so an admin edit or an accepted
  // swap made mid-day is still caught. -----
  const breakNotifiedToday = new Set();
  let breakWatcherTimer = null;
  async function checkMyBreakTimes() {
    if (!currentUserEmail) return;
    const { data, error } = await sb.from('break_schedule')
      .select('break1_time, break2_time, break3_time')
      .eq('employee_email', currentUserEmail).eq('work_date', todayDateStr()).maybeSingle();
    if (error || !data) return;
    const now = new Date();
    const nowHM = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
    [1, 2, 3].forEach(slot => {
      const t = data['break' + slot + '_time'];
      if (!t) return;
      const key = todayDateStr() + '-' + slot;
      if (t.slice(0, 5) === nowHM && !breakNotifiedToday.has(key)) {
        breakNotifiedToday.add(key);
        fireBreakNotification(slot, t);
      }
    });
  }
  function fireBreakNotification(slot, timeStr) {
    const isAr = currentLang === 'ar';
    const title = isAr ? 'حان وقت بريكك! ☕' : 'Break time! ☕';
    const body = isAr ? `بريك ${slot} — الساعة ${formatBreakTime(timeStr)}` : `Break ${slot} — ${formatBreakTime(timeStr)}`;
    playBreakAlertSound();
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try { new Notification(title, { body, icon: '/icons/icon-192.png' }); } catch (e) { /* best-effort only */ }
    }
    showToast(`🔔 ${title} — ${body}`, 'success');
  }
  function playBreakAlertSound() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const beep = (freq, start, dur) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.0001, ctx.currentTime + start);
        gain.gain.exponentialRampToValueAtTime(0.28, ctx.currentTime + start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + dur);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(ctx.currentTime + start);
        osc.stop(ctx.currentTime + start + dur + 0.05);
      };
      beep(880, 0, 0.18);
      beep(1108, 0.22, 0.22);
    } catch (e) { /* audio unavailable — the visible toast/notification still fired */ }
  }
  function startBreakWatcher() {
    stopBreakWatcher();
    checkMyBreakTimes();
    breakWatcherTimer = setInterval(checkMyBreakTimes, 20000);
  }
  function stopBreakWatcher() {
    if (breakWatcherTimer) { clearInterval(breakWatcherTimer); breakWatcherTimer = null; }
  }
  // ===================== End Break Schedule =====================

  // ===================== Training Center (مركز التدريب) — Supabase-driven =====================
  // البيانات هلأ Dynamic بالكامل ومخزّنة بـ Supabase (جداول training_problems / training_nodes / training_options)
  // بدل المصفوفة الثابتة يلي كانت بالكود سابقاً. الأدمن يقدر يدير كل شي من "Admin Portal".
  // شكل الكاش المحلي بعد التحميل:
  //   TRAINING_PROBLEMS: [{ id, key, icon, color, title, titleAr, description, descriptionAr,
  //                          rootNodeId, sortOrder, isActive,
  //                          nodesById: { [nodeId]: { id, nodeType:'question'|'end', question, questionAr,
  //                                                    isActive, sortOrder,
  //                                                    solutionAction, solutionActionAr, solutionPolicy, solutionPolicyAr,
  //                                                    solutionSteps, solutionStepsAr,
  //                                                    options:[{ id, label, labelAr, nextNodeId, sortOrder }] } } }]
  let TRAINING_PROBLEMS = [];

  async function loadTrainingData() {
    const [probRes, nodeRes, optRes] = await Promise.all([
      sb.from('training_problems').select('*').order('sort_order', { ascending: true }),
      sb.from('training_nodes').select('*').order('sort_order', { ascending: true }),
      sb.from('training_options').select('*').order('sort_order', { ascending: true })
    ]);
    if (probRes.error || nodeRes.error || optRes.error) {
      console.warn('تعذّر تحميل بيانات مركز التدريب:', (probRes.error || nodeRes.error || optRes.error).message);
      TRAINING_PROBLEMS = [];
      return;
    }
    const nodesByProblem = {};
    (nodeRes.data || []).forEach(n => { (nodesByProblem[n.problem_id] = nodesByProblem[n.problem_id] || []).push(n); });
    const optionsByNode = {};
    (optRes.data || []).forEach(o => { (optionsByNode[o.node_id] = optionsByNode[o.node_id] || []).push(o); });

    TRAINING_PROBLEMS = (probRes.data || []).map(p => {
      const nodesById = {};
      (nodesByProblem[p.id] || []).forEach(n => {
        nodesById[n.id] = {
          id: n.id,
          nodeType: n.node_type,
          question: n.question || '', questionAr: n.question_ar || '',
          isActive: n.is_active, sortOrder: n.sort_order,
          solutionAction: n.solution_action || '', solutionActionAr: n.solution_action_ar || '',
          solutionPolicy: n.solution_policy || '', solutionPolicyAr: n.solution_policy_ar || '',
          solutionSteps: n.solution_steps || '', solutionStepsAr: n.solution_steps_ar || '',
          options: (optionsByNode[n.id] || []).map(o => ({ id: o.id, label: o.label || '', labelAr: o.label_ar || '', nextNodeId: o.next_node_id, sortOrder: o.sort_order }))
        };
      });
      return {
        id: p.id, key: p.key, icon: p.icon || '📋', color: p.color || '#2563EB',
        title: p.title || '', titleAr: p.title_ar || '',
        description: p.description || '', descriptionAr: p.description_ar || '',
        rootNodeId: p.root_node_id, sortOrder: p.sort_order, isActive: p.is_active,
        nodesById
      };
    });
  }

  let currentTrainingProblem = null;
  let currentTrainingNodeId = null;
  let trainingAnswerTrail = []; // [{ question, chosen }]

  function openTrainingPage() {
    closePanels();
    closeScriptsPage();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTechPage();
    closeBreaksPage();
    document.getElementById('trainingPage').classList.add('open');
    backToTrainingGrid();
    pauseAllOrbits();
    pauseCmdHero();
    orbitControllers.orbitCanvasTraining.start();
  }
  function closeTrainingPage() {
    document.getElementById('trainingPage').classList.remove('open');
    orbitControllers.orbitCanvasTraining.stop();
    orbitControllers.orbitCanvasHome.start();
    resumeCmdHero();
  }

  function renderTrainingGrid() {
    const isAr = currentLang === 'ar';
    const grid = document.getElementById('trainingGrid');
    if (!grid) return;
    const q = (document.getElementById('trainingSearchInput')?.value || '').toLowerCase().trim();
    let visibleProblems = TRAINING_PROBLEMS.filter(p => p.isActive);
    const headCount = document.getElementById('trainingHeadCount');
    if (headCount) headCount.textContent = visibleProblems.length ? (isAr ? `${visibleProblems.length} سيناريو تدريبي` : `${visibleProblems.length} training scenarios`) : '';
    if (q) {
      visibleProblems = visibleProblems.filter(p => {
        const pool = [p.title, p.titleAr, p.description, p.descriptionAr].filter(Boolean).join(' ').toLowerCase();
        return pool.includes(q);
      });
    }
    if (!visibleProblems.length) {
      const noneMatched = q && TRAINING_PROBLEMS.some(p => p.isActive);
      grid.innerHTML = `<div class="empty-state"><span class="empty-icon">🎓</span><strong>${noneMatched ? (isAr ? 'لا توجد نتائج مطابقة' : 'No matching results') : (isAr ? 'لا توجد مواضيع تدريب منشورة بعد' : 'No published training topics yet')}</strong><div style="margin-top:6px;font-size:12px">${noneMatched ? (isAr ? 'جرّب كلمة بحث أخرى.' : 'Try a different search term.') : (isAr ? 'راجع الأدمن لإضافة محتوى مركز التدريب.' : 'Ask your admin to add training content.')}</div></div>`;
      return;
    }
    grid.innerHTML = visibleProblems.map(p => {
      const title = isAr ? p.titleAr : p.title;
      const desc = isAr ? p.descriptionAr : p.description;
      const illus = renderTrainingIllustration(p.icon, p.color, 'training-illus-card');
      const iconHtml = illus || `<div class="training-card-icon-legacy">${escapeHtml(p.icon)}</div>`;
      return `<div class="card training-card" style="--card-accent:${safeColor(p.color)}" data-training-id="${p.id}">
        ${iconHtml}
        <div class="training-card-body">
          <div class="training-card-title">${escapeHtml(title || '—')}</div>
          <div class="training-card-desc">${escapeHtml(desc || '')}</div>
          <span class="training-card-more">${isAr ? 'التفاصيل' : 'Learn more'} ${isAr ? '←' : '→'}</span>
        </div>
      </div>`;
    }).join('');
  }

  function backToTrainingGrid() {
    currentTrainingProblem = null;
    currentTrainingNodeId = null;
    trainingAnswerTrail = [];
    document.getElementById('trainingGridView').style.display = 'block';
    document.getElementById('trainingTreeView').style.display = 'none';
    renderTrainingGrid();
  }

  function openTrainingTree(problemId) {
    const problem = TRAINING_PROBLEMS.find(p => p.id === problemId && p.isActive);
    if (!problem) return;
    markOnboardingStepDone('training');
    currentTrainingProblem = problem;
    currentTrainingNodeId = problem.rootNodeId;
    trainingAnswerTrail = [];
    document.getElementById('trainingGridView').style.display = 'none';
    document.getElementById('trainingTreeView').style.display = 'block';
    renderTrainingTreeHead();
    renderTrainingStage();
    document.getElementById('trainingTreeView').scrollIntoView({ block: 'start' });
  }

  function renderTrainingTreeHead() {
    const isAr = currentLang === 'ar';
    const p = currentTrainingProblem;
    if (!p) return;
    const treeIconEl = document.getElementById('trainingTreeIcon');
    const def = TRAINING_ICON_DEFS[p.icon];
    if (def) {
      const color = safeColor(p.color);
      treeIconEl.innerHTML = `<svg viewBox="0 0 100 100" style="width:26px;height:26px;">${def(shadeHex(color, 0.55), color, shadeHex(color, -0.28))}</svg>`;
    } else {
      treeIconEl.textContent = p.icon;
    }
    treeIconEl.style.setProperty('--training-accent', safeColor(p.color));
    document.getElementById('trainingTreeTitle').textContent = isAr ? p.titleAr : p.title;
    const stage = document.getElementById('trainingTreeStage');
    if (stage) stage.style.setProperty('--training-accent', safeColor(p.color));
  }

  function selectTrainingOption(questionText, chosenLabel, nextNodeId) {
    if (!nextNodeId) {
      showToast(currentLang === 'ar' ? 'هذا الخيار غير مرتبط بخطوة تالية بعد.' : 'This option is not linked to a next step yet.', 'error');
      return;
    }
    trainingAnswerTrail.push({ question: questionText, chosen: chosenLabel });
    currentTrainingNodeId = nextNodeId;
    renderTrainingStage();
  }

  function restartTrainingTree() {
    if (!currentTrainingProblem) return;
    currentTrainingNodeId = currentTrainingProblem.rootNodeId;
    trainingAnswerTrail = [];
    renderTrainingStage();
  }

  function trainingSolutionField(node, isAr, key) {
    const val = isAr ? node[key + 'Ar'] : node[key];
    return val || '';
  }

  function renderTrainingStage() {
    const isAr = currentLang === 'ar';
    const stage = document.getElementById('trainingTreeStage');
    if (!stage || !currentTrainingProblem) return;
    const node = currentTrainingProblem.nodesById[currentTrainingNodeId];
    const problemColor = safeColor(currentTrainingProblem.color);
    const problemIcon = currentTrainingProblem.icon;

    let html = '<div class="training-trail">';
    trainingAnswerTrail.forEach(step => {
      html += `<div class="training-node-card answered">
        <span class="training-answered-q">${escapeHtml(step.question)}</span>
        <span class="training-answered-a">${escapeHtml(step.chosen)}</span>
      </div>
      <div class="training-connector"></div>`;
    });

    if (!node) {
      html += `<div class="training-node-card active" style="text-align:center;">
        <p class="training-question">${isAr ? 'تعذّر العثور على هذه الخطوة (ربما تم حذفها).' : 'This step could not be found (it may have been deleted).'}</p>
        <button class="training-restart-btn" id="trainingRestartBtn">↺ ${isAr ? 'ابدأ من جديد' : 'Start Over'}</button>
      </div>`;
    } else if (!node.isActive) {
      html += `<div class="training-node-card active" style="text-align:center;">
        <p class="training-question">${isAr ? 'هذه الخطوة غير متاحة حالياً.' : 'This step is currently unavailable.'}</p>
        <button class="training-restart-btn" id="trainingRestartBtn">↺ ${isAr ? 'ابدأ من جديد' : 'Start Over'}</button>
      </div>`;
    } else if (node.nodeType === 'end') {
      const fieldLabels = isAr
        ? { solutionAction: 'الإجراء المطلوب' }
        : { solutionAction: 'Required Action' };
      const emptyText = isAr ? 'سيتم إضافة المحتوى قريباً' : 'Content coming soon';
      const fieldHtml = ['solutionAction'].map(fk => {
        const val = trainingSolutionField(node, isAr, fk);
        return `<div class="training-end-field">
          <span class="lbl">${escapeHtml(fieldLabels[fk])}</span>
          <span class="val ${val ? '' : 'empty'}">${escapeHtml(val || emptyText)}</span>
        </div>`;
      }).join('');
      const successIllus = renderTrainingIllustration('check', problemColor, 'training-illus-end');
      html += `<div class="training-end-card" style="--training-accent:${problemColor}">
        ${successIllus || ''}
        <h4 class="training-end-title">${isAr ? 'الحل النهائي' : 'Final Solution'}</h4>
        <div class="training-end-fields">${fieldHtml}</div>
        <button class="training-restart-btn" id="trainingRestartBtn">↺ ${isAr ? 'ابدأ من جديد' : 'Start Over'}</button>
      </div>`;
    } else {
      const questionText = isAr ? node.questionAr : node.question;
      const opts = [...node.options].sort((a, b) => a.sortOrder - b.sortOrder);
      const qIllus = renderTrainingIllustration(problemIcon, problemColor, 'training-illus-question');
      if (!opts.length) {
        html += `<div class="training-node-card active" style="text-align:center;">
          ${qIllus || ''}
          <p class="training-question">${escapeHtml(questionText || (isAr ? '(سؤال بدون نص)' : '(untitled question)'))}</p>
          <p style="font-size:12px;color:var(--slate-soft);margin:0 0 14px;">${isAr ? 'لا توجد خيارات متاحة لهذا السؤال حالياً.' : 'No options are available for this question yet.'}</p>
          <button class="training-restart-btn" id="trainingRestartBtn">↺ ${isAr ? 'ابدأ من جديد' : 'Start Over'}</button>
        </div>`;
      } else {
        const optsHtml = opts.map((opt, i) => {
          const label = isAr ? opt.labelAr : opt.label;
          return `<button class="training-opt-btn" data-opt-index="${i}">${escapeHtml(label || '—')}</button>`;
        }).join('');
        html += `<div class="training-node-card active">
          ${qIllus || ''}
          <p class="training-question">${escapeHtml(questionText || '—')}</p>
          <div class="training-options">${optsHtml}</div>
        </div>`;
      }
    }
    html += '</div>';
    stage.innerHTML = html;

    const restartBtn = document.getElementById('trainingRestartBtn');
    if (restartBtn) restartBtn.addEventListener('click', restartTrainingTree);

    if (node && node.isActive && node.nodeType !== 'end') {
      const questionText = isAr ? node.questionAr : node.question;
      const opts = [...node.options].sort((a, b) => a.sortOrder - b.sortOrder);
      stage.querySelectorAll('.training-opt-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const opt = opts[parseInt(btn.dataset.optIndex, 10)];
          if (!opt) return;
          const chosenLabel = isAr ? opt.labelAr : opt.label;
          selectTrainingOption(questionText, chosenLabel, opt.nextNodeId);
        });
      });
    }
  }
  // ===================== End Training Center (public) =====================

  // ===================== Training Center — Admin (CRUD + Tree Builder + Validation + Preview) =====================
  let trainingAdminSub = 'dashboard';
  let selectedAdminProblemId = null;
  let previewProblemId = null;
  let previewNodeId = null;
  let previewTrail = [];

  function switchTrainingSub(sub) {
    trainingAdminSub = sub;
    document.getElementById('tbPaneDashboard').style.display = sub === 'dashboard' ? 'block' : 'none';
    document.getElementById('tbPaneProblems').style.display = sub === 'problems' ? 'block' : 'none';
    document.getElementById('tbPanePreview').style.display = sub === 'preview' ? 'block' : 'none';
    document.getElementById('tbSubDashboard').classList.toggle('active', sub === 'dashboard');
    document.getElementById('tbSubProblems').classList.toggle('active', sub === 'problems');
    document.getElementById('tbSubPreview').classList.toggle('active', sub === 'preview');
    if (sub === 'dashboard') renderTrainingDashboard();
    else if (sub === 'problems') { renderTrainingProblemsList(); renderTrainingProblemEditor(); }
    else if (sub === 'preview') renderTrainingPreviewSelect();
  }

  // ---------- Validation ----------
  function computeTrainingIssues(problem) {
    const issues = [];
    const nodes = Object.values(problem.nodesById);
    const problemLabel = problem.titleAr || problem.title || problem.key;

    if (!problem.rootNodeId || !problem.nodesById[problem.rootNodeId]) {
      issues.push({ problemId: problem.id, nodeId: null, level: 'error', message: `"${problemLabel}": لم يتم تحديد بداية للشجرة (Root Node)` });
    }

    nodes.forEach(n => {
      if (n.nodeType === 'question') {
        if (!n.question && !n.questionAr) {
          issues.push({ problemId: problem.id, nodeId: n.id, level: 'error', message: `"${problemLabel}": يوجد سؤال بدون نص` });
        }
        if (!n.options.length) {
          issues.push({ problemId: problem.id, nodeId: n.id, level: 'error', message: `"${problemLabel}": سؤال "${n.questionAr || n.question || '—'}" بدون أي خيارات` });
        }
        n.options.forEach(o => {
          if (!o.label && !o.labelAr) {
            issues.push({ problemId: problem.id, nodeId: n.id, level: 'error', message: `"${problemLabel}": يوجد خيار بدون نص` });
          }
          if (!o.nextNodeId) {
            issues.push({ problemId: problem.id, nodeId: n.id, level: 'error', message: `"${problemLabel}": خيار "${o.labelAr || o.label || '—'}" غير مرتبط بأي خطوة تالية` });
          } else if (!problem.nodesById[o.nextNodeId]) {
            issues.push({ problemId: problem.id, nodeId: n.id, level: 'error', message: `"${problemLabel}": خيار "${o.labelAr || o.label || '—'}" يشير إلى عقدة غير موجودة` });
          }
        });
      } else {
        if (!n.solutionAction && !n.solutionActionAr) {
          issues.push({ problemId: problem.id, nodeId: n.id, level: 'warn', message: `"${problemLabel}": نهاية الشجرة بدون "الإجراء المطلوب" بعد` });
        }
      }
    });

    // الوصولية: عقد غير متصلة بالشجرة من البداية
    if (problem.rootNodeId) {
      const reachable = new Set();
      const stack = [problem.rootNodeId];
      while (stack.length) {
        const id = stack.pop();
        if (reachable.has(id)) continue;
        reachable.add(id);
        const n = problem.nodesById[id];
        if (n && n.nodeType === 'question') n.options.forEach(o => { if (o.nextNodeId) stack.push(o.nextNodeId); });
      }
      nodes.forEach(n => {
        if (n.id !== problem.rootNodeId && !reachable.has(n.id)) {
          issues.push({ problemId: problem.id, nodeId: n.id, level: 'warn', message: `"${problemLabel}": عقدة غير متصلة بالشجرة (لا يمكن الوصول إليها من البداية)` });
        }
      });

      // كشف الحلقات الدائرية (Circular loops)
      const cycleSeen = new Set();
      (function dfs(id, path) {
        if (path.includes(id)) {
          if (!cycleSeen.has(id)) {
            cycleSeen.add(id);
            issues.push({ problemId: problem.id, nodeId: id, level: 'warn', message: `"${problemLabel}": تحذير — حلقة دائرية محتملة داخل الشجرة (تأكد أنها مقصودة)` });
          }
          return;
        }
        const n = problem.nodesById[id];
        if (!n || n.nodeType !== 'question') return;
        n.options.forEach(o => { if (o.nextNodeId) dfs(o.nextNodeId, [...path, id]); });
      })(problem.rootNodeId, []);
    }

    return issues;
  }

  function computeAllTrainingIssues() {
    return TRAINING_PROBLEMS.reduce((all, p) => all.concat(computeTrainingIssues(p)), []);
  }

  // ---------- Dashboard ----------
  function renderTrainingDashboard() {
    const totalNodes = TRAINING_PROBLEMS.reduce((n, p) => n + Object.keys(p.nodesById).length, 0);
    const totalOptions = TRAINING_PROBLEMS.reduce((n, p) => n + Object.values(p.nodesById).reduce((m, nd) => m + (nd.options ? nd.options.length : 0), 0), 0);
    const issues = computeAllTrainingIssues();

    document.getElementById('tbStatProblems').textContent = TRAINING_PROBLEMS.length;
    document.getElementById('tbStatNodes').textContent = totalNodes;
    document.getElementById('tbStatOptions').textContent = totalOptions;
    document.getElementById('tbStatIssues').textContent = issues.length;

    const list = document.getElementById('tbIssuesList');
    if (!issues.length) {
      list.innerHTML = `<div class="tb-issue-ok">✅ لا توجد أي ملاحظات — الشجرة سليمة بالكامل.</div>`;
      return;
    }
    list.innerHTML = issues.map(iss => `
      <div class="tb-issue-row ${iss.level}">
        <span class="tb-issue-icon">${iss.level === 'error' ? '⛔' : '⚠️'}</span>
        <span class="tb-issue-text">${escapeHtml(iss.message)}</span>
        <button class="tb-mini-btn" data-goto-problem="${iss.problemId}">🔧 إدارة</button>
      </div>
    `).join('');
  }

  // ---------- Problems list ----------
  function renderTrainingProblemsList() {
    const list = document.getElementById('tbProblemsList');
    if (!list) return;
    if (!TRAINING_PROBLEMS.length) {
      list.innerHTML = `<div class="tb-empty-hint">لا توجد أي مشاكل تدريب بعد — أنشئ أول مشكلة من الأعلى.</div>`;
      return;
    }
    list.innerHTML = TRAINING_PROBLEMS.map(p => {
      const nodeCount = Object.keys(p.nodesById).length;
      const issueCount = computeTrainingIssues(p).length;
      return `<div class="tb-problem-pill ${selectedAdminProblemId === p.id ? 'active' : ''}" data-select-problem="${p.id}" style="--tb-accent:${safeColor(p.color)}">
        <span class="tb-problem-pill-icon">${escapeHtml(p.icon)}</span>
        <span class="tb-problem-pill-title">${escapeHtml(p.titleAr || p.title || p.key)}</span>
        <span class="tb-problem-pill-meta">${nodeCount} عقدة${issueCount ? ` · ⚠️ ${issueCount}` : ''}</span>
        <span class="tb-problem-pill-status ${p.isActive ? 'on' : 'off'}">${p.isActive ? 'منشور' : 'مسودة'}</span>
      </div>`;
    }).join('');
  }

  // ---------- Problem editor (meta + tree outline) ----------
  function renderTrainingProblemEditor() {
    const editor = document.getElementById('tbProblemEditor');
    if (!editor) return;
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    if (!p) { editor.innerHTML = ''; return; }

    const nodes = Object.values(p.nodesById).sort((a, b) => a.sortOrder - b.sortOrder);
    const reachable = new Set();
    if (p.rootNodeId) {
      const stack = [p.rootNodeId];
      while (stack.length) {
        const id = stack.pop();
        if (reachable.has(id)) continue;
        reachable.add(id);
        const n = p.nodesById[id];
        if (n && n.nodeType === 'question') n.options.forEach(o => { if (o.nextNodeId) stack.push(o.nextNodeId); });
      }
    }
    const orphanNodes = nodes.filter(n => n.id !== p.rootNodeId && !reachable.has(n.id));

    let html = `
      <div class="tb-meta-card" style="--tb-accent:${safeColor(p.color)}">
        <div class="tb-meta-row">
          <input type="hidden" id="tbMetaIcon" value="${escapeHtml(p.icon)}">
          <input type="color" id="tbMetaColor" value="${safeColor(p.color)}" style="width:40px;height:38px;border:none;border-radius:6px;cursor:pointer;">
          <input type="text" id="tbMetaTitle" value="${escapeHtml(p.title)}" placeholder="العنوان بالإنجليزية">
          <input type="text" id="tbMetaTitleAr" value="${escapeHtml(p.titleAr)}" placeholder="العنوان بالعربية">
        </div>
        <div class="tb-icon-picker" id="tbIconPicker">${TRAINING_ICON_KEYS.map(key => `
          <button type="button" class="tb-icon-opt ${p.icon === key ? 'selected' : ''}" data-icon-key="${key}" title="${key}">
            <svg viewBox="0 0 100 100">${TRAINING_ICON_DEFS[key](shadeHex(safeColor(p.color), 0.55), safeColor(p.color), shadeHex(safeColor(p.color), -0.28))}</svg>
          </button>`).join('')}
        </div>
        ${!TRAINING_ICON_DEFS[p.icon] ? `<p class="tb-icon-legacy-note">الأيقونة الحالية: ${escapeHtml(p.icon)} — اختر رسمة من فوق لاستبدالها</p>` : ''}
        <div class="tb-meta-row">
          <input type="text" id="tbMetaDesc" value="${escapeHtml(p.description)}" placeholder="وصف قصير بالإنجليزية">
          <input type="text" id="tbMetaDescAr" value="${escapeHtml(p.descriptionAr)}" placeholder="وصف قصير بالعربية">
        </div>
        <div class="tb-meta-row" style="align-items:center;">
          <label class="tb-active-toggle"><input type="checkbox" id="tbMetaActive" ${p.isActive ? 'checked' : ''}> منشور للموظفين</label>
          <button class="tb-mini-btn primary" id="btnSaveProblemMeta">💾 حفظ بيانات المشكلة</button>
          <button class="tb-mini-btn danger" id="btnDeleteProblem" data-delete-problem="${p.id}">🗑️ حذف المشكلة بالكامل</button>
        </div>
      </div>

      <div class="tb-tree-toolbar">
        <span class="tb-mini-title" style="margin:0;">🌳 شجرة الأسئلة</span>
        <button class="tb-mini-btn" data-add-node="question">+ سؤال جديد</button>
        <button class="tb-mini-btn" data-add-node="end">+ رسالة نهائية (End Node)</button>
      </div>
      <div class="tb-tree-outline">`;

    if (!p.rootNodeId || !p.nodesById[p.rootNodeId]) {
      html += `<div class="tb-empty-hint">⚠️ لم يتم تحديد بداية للشجرة بعد. أنشئ عقدة وحدد "تعيين كبداية" عليها.</div>`;
    } else {
      html += renderTrainingNodeOutline(p, p.rootNodeId, []);
    }
    html += `</div>`;

    if (orphanNodes.length) {
      html += `<div class="tb-tree-toolbar" style="margin-top:18px;"><span class="tb-mini-title" style="margin:0;">🧩 عقد غير مرتبطة بالشجرة</span></div><div class="tb-tree-outline">`;
      orphanNodes.forEach(n => { html += renderTrainingNodeCard(p, n, false); });
      html += `</div>`;
    }

    editor.innerHTML = html;
  }

  function renderTrainingNodeOutline(problem, nodeId, path) {
    const node = problem.nodesById[nodeId];
    if (!node) return `<div class="tb-issue-row error"><span class="tb-issue-icon">⛔</span><span class="tb-issue-text">عقدة مفقودة (ID: ${escapeHtml(nodeId)})</span></div>`;
    if (path.includes(nodeId)) {
      return `<div class="tb-issue-row warn"><span class="tb-issue-icon">🔁</span><span class="tb-issue-text">حلقة دائرية — رجوع إلى: "${escapeHtml(node.questionAr || node.question || '—')}"</span></div>`;
    }
    let html = renderTrainingNodeCard(problem, node, node.id === problem.rootNodeId);
    if (node.nodeType === 'question') {
      const opts = [...node.options].sort((a, b) => a.sortOrder - b.sortOrder);
      opts.forEach(opt => {
        if (opt.nextNodeId && problem.nodesById[opt.nextNodeId]) {
          html += `<div class="tb-branch-wrap">
            <div class="tb-branch-line"><span class="tb-branch-label">${escapeHtml(opt.labelAr || opt.label || '—')}</span></div>
            ${renderTrainingNodeOutline(problem, opt.nextNodeId, [...path, nodeId])}
          </div>`;
        }
      });
    }
    return html;
  }

  function renderTrainingNodeCard(problem, node, isRoot) {
    const isAr = true; // لوحة الأدمن عربية دائماً لتبسيط الإدارة
    const nodeIssues = computeTrainingIssues(problem).filter(i => i.nodeId === node.id);
    const hasError = nodeIssues.some(i => i.level === 'error');
    let inner = '';

    if (node.nodeType === 'end') {
      inner = `
        <div class="tb-field-row">
          <label>الإجراء المطلوب (عربي)</label>
          <textarea id="tbn-${node.id}-actAr" rows="2">${escapeHtml(node.solutionActionAr)}</textarea>
          <label>Required Action (English)</label>
          <textarea id="tbn-${node.id}-act" rows="2">${escapeHtml(node.solutionAction)}</textarea>
        </div>`;
    } else {
      inner = `
        <div class="tb-field-row">
          <label>السؤال (عربي)</label>
          <textarea id="tbn-${node.id}-qAr" rows="2">${escapeHtml(node.questionAr)}</textarea>
          <label>Question (English)</label>
          <textarea id="tbn-${node.id}-q" rows="2">${escapeHtml(node.question)}</textarea>
        </div>
        <div class="tb-options-block">
          <div class="tb-options-head"><span>الخيارات (Options)</span><button class="tb-mini-btn" data-add-option="${node.id}">+ إضافة خيار</button></div>
          ${[...node.options].sort((a, b) => a.sortOrder - b.sortOrder).map(opt => renderTrainingOptionRow(problem, node, opt)).join('') || '<div class="tb-empty-hint">لا توجد خيارات — أضف خياراً وإلا لن يستطيع الموظف المتابعة.</div>'}
        </div>`;
    }

    return `<div class="tb-node-card ${hasError ? 'has-error' : ''}" style="--tb-accent:${safeColor(problem.color)}" data-node-card="${node.id}">
      <div class="tb-node-head">
        <span class="tb-node-type-badge ${node.nodeType}">${node.nodeType === 'end' ? '🏁 نهائي' : '❓ سؤال'}</span>
        ${isRoot ? '<span class="tb-root-badge">⭐ بداية الشجرة</span>' : `<button class="tb-mini-btn" data-set-root="${node.id}" data-problem-for-root="${problem.id}">🎯 تعيين كبداية</button>`}
        <label class="tb-active-toggle"><input type="checkbox" ${node.isActive ? 'checked' : ''} data-toggle-node-active="${node.id}"> مفعّل</label>
        <button class="tb-mini-btn danger" data-delete-node="${node.id}" title="حذف">🗑️</button>
      </div>
      ${inner}
      <button class="tb-mini-btn primary" data-save-node="${node.id}">💾 حفظ العقدة</button>
      ${nodeIssues.length ? `<div class="tb-node-issues">${nodeIssues.map(i => `<span class="tb-node-issue-chip ${i.level}">${i.level === 'error' ? '⛔' : '⚠️'} ${escapeHtml(i.message.split('": ')[1] || i.message)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  function renderTrainingOptionRow(problem, node, opt) {
    const nodeOptionsForSelect = Object.values(problem.nodesById)
      .filter(n => n.id !== node.id)
      .sort((a, b) => a.sortOrder - b.sortOrder)
      .map(n => {
        const label = (n.nodeType === 'end' ? '🏁 ' : '❓ ') + (n.questionAr || n.question || n.solutionActionAr || n.solutionAction || '(بدون نص)');
        return `<option value="${n.id}" ${opt.nextNodeId === n.id ? 'selected' : ''}>${escapeHtml(label.slice(0, 60))}</option>`;
      }).join('');
    return `<div class="tb-option-row" data-option-row="${opt.id}">
      <input type="text" id="tbo-${opt.id}-labelAr" value="${escapeHtml(opt.labelAr)}" placeholder="نص الخيار (عربي)">
      <input type="text" id="tbo-${opt.id}-label" value="${escapeHtml(opt.label)}" placeholder="Option text (English)">
      <select id="tbo-${opt.id}-next">
        <option value="">— غير مرتبط —</option>
        ${nodeOptionsForSelect}
      </select>
      <button class="tb-mini-btn primary" data-save-option="${opt.id}" title="حفظ">💾</button>
      <button class="tb-mini-btn danger" data-delete-option="${opt.id}" title="حذف">🗑️</button>
    </div>`;
  }

  // ---------- Problem CRUD ----------
  async function createTrainingProblem() {
    const isAr = currentLang === 'ar';
    const icon = document.getElementById('newProblemIcon').value.trim() || 'list';
    const color = document.getElementById('newProblemColor').value || '#2563EB';
    const title = document.getElementById('newProblemTitle').value.trim();
    const titleAr = document.getElementById('newProblemTitleAr').value.trim();
    if (!(title || titleAr)) { showToast(isAr ? 'يرجى إدخال عنوان المشكلة.' : 'Please enter a problem title.', 'error'); return; }

    let baseKey = (title || titleAr).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'problem';
    let key = baseKey, n = 1;
    const existingKeys = new Set(TRAINING_PROBLEMS.map(p => p.key));
    while (existingKeys.has(key)) { n++; key = `${baseKey}_${n}`; }
    const maxSort = TRAINING_PROBLEMS.reduce((m, p) => Math.max(m, p.sortOrder || 0), 0);

    const { data, error } = await sb.from('training_problems').insert({
      key, icon, color, title: title || titleAr, title_ar: titleAr || title,
      description: '', description_ar: '', sort_order: maxSort + 1, is_active: false
    }).select().single();
    if (error) { showToast(isAr ? 'تعذّر إنشاء المشكلة.' : 'Could not create the problem.', 'error'); return; }

    const { data: nodeData, error: nodeErr } = await sb.from('training_nodes').insert({
      problem_id: data.id, node_type: 'question', question: '', question_ar: '', is_active: true, sort_order: 0
    }).select().single();
    if (!nodeErr && nodeData) {
      await sb.from('training_problems').update({ root_node_id: nodeData.id }).eq('id', data.id);
    }

    document.getElementById('newProblemTitle').value = '';
    document.getElementById('newProblemTitleAr').value = '';
    document.getElementById('newProblemIcon').value = '';
    await loadTrainingData();
    selectedAdminProblemId = data.id;
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم إنشاء المشكلة! أضف الأسئلة الآن.' : 'Problem created! Now add your questions.', 'success');
  }

  function selectAdminProblem(problemId) {
    selectedAdminProblemId = problemId;
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
  }

  async function saveTrainingProblemMeta() {
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    if (!p) return;
    const payload = {
      icon: document.getElementById('tbMetaIcon').value.trim() || '📋',
      color: document.getElementById('tbMetaColor').value || '#2563EB',
      title: document.getElementById('tbMetaTitle').value.trim(),
      title_ar: document.getElementById('tbMetaTitleAr').value.trim(),
      description: document.getElementById('tbMetaDesc').value.trim(),
      description_ar: document.getElementById('tbMetaDescAr').value.trim(),
      is_active: document.getElementById('tbMetaActive').checked
    };
    if (!(payload.title || payload.title_ar)) { showToast(isAr ? 'يرجى إدخال عنوان المشكلة.' : 'Please enter a title.', 'error'); return; }
    payload.title = payload.title || payload.title_ar;
    payload.title_ar = payload.title_ar || payload.title;
    const { error } = await sb.from('training_problems').update(payload).eq('id', p.id);
    if (error) { showToast(isAr ? 'تعذّر حفظ التعديلات.' : 'Could not save changes.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم حفظ بيانات المشكلة.' : 'Problem details saved.', 'success');
  }

  async function deleteTrainingProblem(problemId) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === problemId);
    if (!p) return;
    const nodeCount = Object.keys(p.nodesById).length;
    const msg = isAr
      ? `هل أنت متأكد من حذف مشكلة "${p.titleAr || p.title}"؟ سيتم حذف جميع أسئلتها (${nodeCount}) وخياراتها نهائياً، ولا يمكن التراجع.`
      : `Delete problem "${p.title}"? All its ${nodeCount} questions and options will be permanently deleted.`;
    if (!confirm(msg)) return;
    const { error } = await sb.from('training_problems').delete().eq('id', problemId);
    if (error) { showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error'); return; }
    if (selectedAdminProblemId === problemId) selectedAdminProblemId = null;
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم حذف المشكلة.' : 'Problem deleted.', 'success');
  }

  // ---------- Node CRUD ----------
  async function addTrainingNode(nodeType) {
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    if (!p) return;
    const maxSort = Object.values(p.nodesById).reduce((m, n) => Math.max(m, n.sortOrder || 0), -1);
    const { error } = await sb.from('training_nodes').insert({
      problem_id: p.id, node_type: nodeType, question: '', question_ar: '',
      is_active: true, sort_order: maxSort + 1
    });
    if (error) { showToast(isAr ? 'تعذّر إضافة العقدة.' : 'Could not add the node.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تمت إضافة العقدة. لا تنسَ ربطها بخيار أو تعيينها كبداية.' : 'Node added. Remember to link it from an option or set it as root.', 'success');
  }

  function collectNodeFieldsFromDom(node) {
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    if (node.nodeType === 'end') {
      return {
        solution_action: g(`tbn-${node.id}-act`), solution_action_ar: g(`tbn-${node.id}-actAr`)
      };
    }
    return { question: g(`tbn-${node.id}-q`), question_ar: g(`tbn-${node.id}-qAr`) };
  }

  async function saveTrainingNode(nodeId) {
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    const node = p && p.nodesById[nodeId];
    if (!node) return;
    const payload = collectNodeFieldsFromDom(node);
    const { error } = await sb.from('training_nodes').update(payload).eq('id', nodeId);
    if (error) { showToast(isAr ? 'تعذّر الحفظ.' : 'Could not save.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم حفظ العقدة.' : 'Node saved.', 'success');
  }

  async function toggleTrainingNodeActive(nodeId, isActive) {
    const { error } = await sb.from('training_nodes').update({ is_active: isActive }).eq('id', nodeId);
    if (error) { showToast(currentLang === 'ar' ? 'تعذّر التحديث.' : 'Could not update.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
  }

  async function deleteTrainingNode(nodeId) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    const node = p && p.nodesById[nodeId];
    if (!node) return;
    let incomingCount = 0;
    Object.values(p.nodesById).forEach(n => { n.options.forEach(o => { if (o.nextNodeId === nodeId) incomingCount++; }); });
    const isRoot = p.rootNodeId === nodeId;
    let msg = isAr ? 'هل أنت متأكد من حذف هذه العقدة؟' : 'Delete this node?';
    if (incomingCount > 0) msg += isAr ? `\n\nتحذير: يوجد ${incomingCount} خيار مرتبط بها حالياً — سيصبح غير مرتبط (Unlinked) بعد الحذف.` : `\n\nWarning: ${incomingCount} option(s) currently link to it — they will become unlinked.`;
    if (isRoot) msg += isAr ? '\n\n⚠️ هذه هي بداية الشجرة الحالية! يجب تعيين بداية جديدة بعد الحذف.' : '\n\n⚠️ This is the current root node! You will need to set a new root after deleting.';
    if (!confirm(msg)) return;
    const { error } = await sb.from('training_nodes').delete().eq('id', nodeId);
    if (error) { showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم حذف العقدة.' : 'Node deleted.', 'success');
  }

  async function setTrainingRootNode(problemId, nodeId) {
    const isAr = currentLang === 'ar';
    const { error } = await sb.from('training_problems').update({ root_node_id: nodeId }).eq('id', problemId);
    if (error) { showToast(isAr ? 'تعذّر التحديث.' : 'Could not update.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم تحديد بداية الشجرة.' : 'Root node set.', 'success');
  }

  // ---------- Option CRUD ----------
  async function addTrainingOption(nodeId) {
    const isAr = currentLang === 'ar';
    const p = TRAINING_PROBLEMS.find(x => x.id === selectedAdminProblemId);
    const node = p && p.nodesById[nodeId];
    if (!node) return;
    const maxSort = node.options.reduce((m, o) => Math.max(m, o.sortOrder || 0), -1);
    const { error } = await sb.from('training_options').insert({ node_id: nodeId, label: '', label_ar: '', sort_order: maxSort + 1 });
    if (error) { showToast(isAr ? 'تعذّر إضافة الخيار.' : 'Could not add the option.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
  }

  async function saveTrainingOption(optionId) {
    const isAr = currentLang === 'ar';
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const nextVal = g(`tbo-${optionId}-next`);
    const payload = {
      label: g(`tbo-${optionId}-label`),
      label_ar: g(`tbo-${optionId}-labelAr`),
      next_node_id: nextVal || null
    };
    const { error } = await sb.from('training_options').update(payload).eq('id', optionId);
    if (error) { showToast(isAr ? 'تعذّر الحفظ.' : 'Could not save.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
    showToast(isAr ? 'تم حفظ الخيار.' : 'Option saved.', 'success');
  }

  async function deleteTrainingOption(optionId) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    if (!confirm(isAr ? 'هل أنت متأكد من حذف هذا الخيار؟' : 'Delete this option?')) return;
    const { error } = await sb.from('training_options').delete().eq('id', optionId);
    if (error) { showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error'); return; }
    await loadTrainingData();
    renderTrainingProblemsList();
    renderTrainingProblemEditor();
  }

  // ---------- Preview mode (admin only — includes drafts, doesn't touch real data) ----------
  function renderTrainingPreviewSelect() {
    const sel = document.getElementById('tbPreviewProblemSelect');
    if (!sel) return;
    sel.innerHTML = `<option value="">— اختر مشكلة —</option>` + TRAINING_PROBLEMS.map(p =>
      `<option value="${p.id}">${escapeHtml(p.icon)} ${escapeHtml(p.titleAr || p.title || p.key)}${p.isActive ? '' : ' (مسودة)'}</option>`
    ).join('');
    sel.value = previewProblemId || '';
    document.getElementById('tbPreviewStage').innerHTML = '';
  }

  function startTrainingPreview(problemId) {
    previewProblemId = problemId;
    const p = TRAINING_PROBLEMS.find(x => x.id === problemId);
    previewNodeId = p ? p.rootNodeId : null;
    previewTrail = [];
    renderTrainingPreviewStage();
  }

  function restartTrainingPreview() {
    const p = TRAINING_PROBLEMS.find(x => x.id === previewProblemId);
    previewNodeId = p ? p.rootNodeId : null;
    previewTrail = [];
    renderTrainingPreviewStage();
  }

  function renderTrainingPreviewStage() {
    const stage = document.getElementById('tbPreviewStage');
    if (!stage) return;
    const p = TRAINING_PROBLEMS.find(x => x.id === previewProblemId);
    if (!p) { stage.innerHTML = ''; return; }
    const node = p.nodesById[previewNodeId];

    let html = `<div class="training-trail" style="--training-accent:${safeColor(p.color)}">`;
    previewTrail.forEach(step => {
      html += `<div class="training-node-card answered">
        <span class="training-answered-q">${escapeHtml(step.question)}</span>
        <span class="training-answered-a">${escapeHtml(step.chosen)}</span>
      </div><div class="training-connector"></div>`;
    });

    if (!node) {
      html += `<div class="training-node-card active" style="text-align:center;"><p class="training-question">لا توجد بداية محددة لهذه المشكلة بعد.</p></div>`;
    } else if (node.nodeType === 'end') {
      const emptyText = 'سيتم إضافة المحتوى قريباً';
      const fields = [
        ['الإجراء المطلوب', node.solutionActionAr || node.solutionAction]
      ];
      html += `<div class="training-end-card">
        <div class="training-end-badge">🎉</div>
        <h4 class="training-end-title">الحل النهائي</h4>
        <div class="training-end-fields">${fields.map(([lbl, val]) => `<div class="training-end-field"><span class="lbl">${escapeHtml(lbl)}</span><span class="val ${val ? '' : 'empty'}">${escapeHtml(val || emptyText)}</span></div>`).join('')}</div>
        <button class="training-restart-btn" id="tbPreviewRestartBtn">↺ ابدأ من جديد</button>
      </div>`;
    } else {
      const questionText = node.questionAr || node.question || '(سؤال بدون نص)';
      const opts = [...node.options].sort((a, b) => a.sortOrder - b.sortOrder);
      if (!opts.length) {
        html += `<div class="training-node-card active" style="text-align:center;">
          <p class="training-question">${escapeHtml(questionText)}</p>
          <p style="font-size:12px;color:var(--slate-soft);margin:0 0 14px;">⚠️ لا توجد خيارات لهذا السؤال بعد.</p>
          <button class="training-restart-btn" id="tbPreviewRestartBtn">↺ ابدأ من جديد</button>
        </div>`;
      } else {
        html += `<div class="training-node-card active">
          <p class="training-question">${escapeHtml(questionText)}</p>
          <div class="training-options">${opts.map((o, i) => `<button class="training-opt-btn" data-preview-opt="${i}">${escapeHtml(o.labelAr || o.label || '—')}</button>`).join('')}</div>
        </div>`;
      }
    }
    html += '</div>';
    stage.innerHTML = html;

    const restartBtn = document.getElementById('tbPreviewRestartBtn');
    if (restartBtn) restartBtn.addEventListener('click', restartTrainingPreview);
    if (node && node.nodeType === 'question') {
      const opts = [...node.options].sort((a, b) => a.sortOrder - b.sortOrder);
      stage.querySelectorAll('[data-preview-opt]').forEach(btn => {
        btn.addEventListener('click', () => {
          const opt = opts[parseInt(btn.dataset.previewOpt, 10)];
          if (!opt) return;
          if (!opt.nextNodeId) { showToast('هذا الخيار غير مرتبط بعد.', 'error'); return; }
          previewTrail.push({ question: node.questionAr || node.question, chosen: opt.labelAr || opt.label });
          previewNodeId = opt.nextNodeId;
          renderTrainingPreviewStage();
        });
      });
    }
  }

  // ---------- Event delegation for the whole Training admin tab ----------
  function bindTrainingAdminEvents() {
    const container = document.getElementById('adminTabTraining');
    if (!container) return;

    document.querySelectorAll('.tb-subnav-btn').forEach(btn => {
      btn.addEventListener('click', () => switchTrainingSub(btn.dataset.trainSub));
    });

    document.getElementById('btnCreateProblem').addEventListener('click', createTrainingProblem);

    container.addEventListener('input', (e) => {
      if (e.target.id === 'tbMetaColor') {
        const color = safeColor(e.target.value);
        const light = shadeHex(color, 0.55), dark = shadeHex(color, -0.28);
        document.querySelectorAll('.tb-icon-opt').forEach(btn => {
          const key = btn.dataset.iconKey;
          const def = TRAINING_ICON_DEFS[key];
          if (def) btn.querySelector('svg').innerHTML = def(light, color, dark);
        });
      }
    });

    container.addEventListener('click', (e) => {
      const iconOptBtn = e.target.closest('.tb-icon-opt');
      if (iconOptBtn) {
        const hiddenInput = document.getElementById('tbMetaIcon');
        if (hiddenInput) hiddenInput.value = iconOptBtn.dataset.iconKey;
        document.querySelectorAll('.tb-icon-opt').forEach(b => b.classList.toggle('selected', b === iconOptBtn));
        return;
      }

      const gotoBtn = e.target.closest('[data-goto-problem]');
      if (gotoBtn) { switchTrainingSub('problems'); selectAdminProblem(gotoBtn.dataset.gotoProblem); return; }

      const selBtn = e.target.closest('[data-select-problem]');
      if (selBtn) { selectAdminProblem(selBtn.dataset.selectProblem); return; }

      const delProblemBtn = e.target.closest('[data-delete-problem]');
      if (delProblemBtn) { deleteTrainingProblem(delProblemBtn.dataset.deleteProblem); return; }

      const saveMetaBtn = e.target.closest('#btnSaveProblemMeta');
      if (saveMetaBtn) { saveTrainingProblemMeta(); return; }

      const addNodeBtn = e.target.closest('[data-add-node]');
      if (addNodeBtn) { addTrainingNode(addNodeBtn.dataset.addNode); return; }

      const saveNodeBtn = e.target.closest('[data-save-node]');
      if (saveNodeBtn) { saveTrainingNode(saveNodeBtn.dataset.saveNode); return; }

      const delNodeBtn = e.target.closest('[data-delete-node]');
      if (delNodeBtn) { deleteTrainingNode(delNodeBtn.dataset.deleteNode); return; }

      const setRootBtn = e.target.closest('[data-set-root]');
      if (setRootBtn) { setTrainingRootNode(setRootBtn.dataset.problemForRoot, setRootBtn.dataset.setRoot); return; }

      const addOptBtn = e.target.closest('[data-add-option]');
      if (addOptBtn) { addTrainingOption(addOptBtn.dataset.addOption); return; }

      const saveOptBtn = e.target.closest('[data-save-option]');
      if (saveOptBtn) { saveTrainingOption(saveOptBtn.dataset.saveOption); return; }

      const delOptBtn = e.target.closest('[data-delete-option]');
      if (delOptBtn) { deleteTrainingOption(delOptBtn.dataset.deleteOption); return; }
    });

    container.addEventListener('change', (e) => {
      const toggle = e.target.closest('[data-toggle-node-active]');
      if (toggle) { toggleTrainingNodeActive(toggle.dataset.toggleNodeActive, toggle.checked); }
    });

    document.getElementById('tbPreviewProblemSelect').addEventListener('change', (e) => {
      startTrainingPreview(e.target.value || null);
    });
  }
  // ===================== End Training Center — Admin =====================

  function toggleLanguage() {
    currentLang = (currentLang === 'ar') ? 'en' : 'ar';
    localStorage.setItem('fajer_lang_v2', currentLang);
    applyLanguage();
    render();
  }

  function applyLanguage() {
    const isAr = currentLang === 'ar';
    document.documentElement.dir = isAr ? 'rtl' : 'ltr';
    document.documentElement.lang = currentLang;

    document.getElementById('langBtnText').textContent = isAr ? 'EN' : 'AR';
    document.getElementById('logoutBtnText').textContent = isAr ? 'خروج' : 'Logout';
    document.getElementById('profileRoleLabel').textContent = isAr ? 'موظف' : 'Employee';
    document.getElementById('searchInput').placeholder = isAr ? 'البحث بالعنوان أو محتوى الرد...' : 'Search by title or response content...';
    document.getElementById('workspaceTitle').textContent = isAr ? 'تصعيد التذكرة' : 'Escalation Ticket';
    document.getElementById('scriptCountLabel').textContent = isAr ? 'سكريبت متاح' : 'available scripts';
    
    const lblQt = document.getElementById('lblQuickTools');
    if (lblQt) lblQt.textContent = isAr ? 'أدوات سريعة' : 'QUICK TOOLS';
    document.getElementById('lblSideGen').textContent = isAr ? 'معلومات عامة' : 'GENERAL INFO';
    document.getElementById('lblSideCrit').textContent = isAr ? 'أخطاء حرجة' : 'CRITICAL MISTAKES';
    document.getElementById('lblSideEtiq').textContent = isAr ? 'بروتوكول المكالمة' : 'ETIQUETTE CALL';
    document.getElementById('lblSideSuggest').textContent = isAr ? 'الاقتراحات' : 'SUGGESTIONS';
    document.getElementById('lblSideContrib').textContent = isAr ? 'ساهم بحل' : 'CONTRIBUTE A FIX';

    document.getElementById('hGenInfo').textContent = isAr ? 'ℹ️ معلومات عامة' : 'ℹ️ General Information';
    document.getElementById('hEtiqCall').textContent = isAr ? '📞 بروتوكول المكالمة' : '📞 Etiquette Call';
    document.getElementById('hCritMist').textContent = isAr ? '⚠ الأخطاء الحرجة' : '⚠ Critical Mistakes';
    document.getElementById('lblUpdDesc').textContent = isAr ? 'أضف تحديثاً جديداً — سيظهر إشعار للفريق تلقائياً:' : 'Add a new update — the team gets a notification automatically:';
    document.getElementById('btnAddUpd').textContent = isAr ? '🔔 نشر التحديث للفريق' : '🔔 Publish Update to Team';

    document.getElementById('updatesPageTitle').textContent = isAr ? '🔔 التحديثات الجديدة' : '🔔 New Updates';
    document.getElementById('updatesPageSub').textContent = isAr ? 'كل شي جديد أو اتغيّر مؤخراً بمكان واحد' : "Everything the team shipped or changed recently, in one place";
    document.getElementById('updatesSearchInput').placeholder = isAr ? 'ابحث بنص التحديث...' : 'Search updates...';
    document.getElementById('updatesSearchLabel').textContent = isAr ? '🔍 بحث' : '🔍 Search';
    document.getElementById('updatesFilterLabel').textContent = isAr ? 'تصفية' : 'Filter';
    document.getElementById('updatesFilterAll').textContent = isAr ? 'الكل' : 'All';
    document.getElementById('updatesFilterWeek').textContent = isAr ? 'هذا الأسبوع' : 'This week';
    document.getElementById('updatesFilterArchive').textContent = isAr ? 'الأرشيف' : 'Archive';
    document.getElementById('updatesStatsLabel').textContent = isAr ? 'إحصائيات' : 'Stats';
    document.getElementById('updatesStatTotalLabel').textContent = isAr ? 'الإجمالي' : 'Total';
    document.getElementById('updatesStatWeekLabel').textContent = isAr ? 'هذا الأسبوع' : 'This week';
    if (document.getElementById('updatesPage').classList.contains('open')) renderUpdatesPage();

    document.getElementById('mentorshipPageTitle').textContent = isAr ? '🤝 الرعاية والتدريب' : '🤝 Mentorship';
    document.getElementById('mentorshipPageSub').textContent = isAr ? 'اطلب راعي تدريب، أو رد على طلب توجيه وصلك' : 'Request a mentor, or respond to a mentorship request you received';
    document.getElementById('mentorNotifyText').textContent = isAr ? 'فعّل الإشعارات حتى توصلك الرسايل حتى لو الموقع مسكر' : 'Turn on notifications to get messages even when the site is closed';
    document.getElementById('mentorNotifyBtnLabel').textContent = isAr ? 'تفعيل' : 'Enable';
    document.getElementById('lblMtabRequest').textContent = isAr ? 'اطلب راعي' : 'Request a Mentor';
    document.getElementById('lblMtabIncoming').textContent = isAr ? 'طلبات واردة' : 'Incoming Requests';
    document.getElementById('lblMtabChats').textContent = isAr ? 'محادثاتي' : 'My Chats';
    document.getElementById('lblMentorEmail').textContent = isAr ? 'دوّر على راعي:' : 'Find a mentor:';
    document.getElementById('mentorRequestNote').placeholder = isAr ? 'ليش بدك ياه راعي؟ (اختياري)' : 'Why do you want them as a mentor? (optional)';
    document.getElementById('btnSendMentorRequest').textContent = isAr ? 'إرسال الطلب' : 'Send Request';
    document.getElementById('lblMyOutgoing').textContent = isAr ? '📨 طلباتي المرسلة' : '📨 My Sent Requests';
    document.getElementById('colOutColleague').textContent = isAr ? 'الزميل' : 'Colleague';
    document.getElementById('colOutReason').textContent = isAr ? 'السبب' : 'Reason';
    document.getElementById('colOutStatus').textContent = isAr ? 'الحالة' : 'Status';
    document.getElementById('colOutDate').textContent = isAr ? 'التاريخ' : 'Date';
    document.getElementById('mentorOutgoingEmptyText').textContent = isAr ? 'ما أرسلت أي طلب رعاية بعد' : "You haven't sent any mentorship requests yet";
    document.getElementById('lblMentorSideCount').textContent = isAr ? 'رسالة' : 'messages';
    if (openMentorThreadId) renderMentorThreadSideProfile(openMentorThreadId);

    document.getElementById('onboardingHeroTitle').textContent = isAr ? 'أهلاً! 👋' : 'Welcome! 👋';
    document.getElementById('onboardingHeroSub').textContent = isAr ? 'هاي أول أسبوع إلك بفريق نوفا — خلّص هاي الخطوات البسيطة حتى تبلش بثقة.' : "This is your first week with the Nova team — finish these simple steps to get started with confidence.";
    document.getElementById('onboardingRingLbl').textContent = isAr ? 'خطوات مكتملة' : 'steps done';
    document.getElementById('lblOnboardingSkip').textContent = isAr ? 'تخطي' : 'Skip';
    if (document.getElementById('onboardingPage').classList.contains('open')) renderOnboardingPage();
    document.getElementById('mentorChatInput').placeholder = isAr ? 'اكتب رسالة...' : 'Write a message...';
    renderMentorEmailOptions();
    if (document.getElementById('mentorshipPage').classList.contains('open')) switchMentorTab(activeMentorTab);

    document.getElementById('hSuggest').textContent = isAr ? '💡 اقتراح جديد' : '💡 New Suggestion';
    document.getElementById('lblSuggestDesc').textContent = isAr ? 'شاركنا اقتراحك لتحسين العمل — يصل مباشرة للإدارة فقط.' : 'Share your suggestion to improve the work — it goes straight to management only.';
    document.getElementById('lblSuggestAs').textContent = isAr ? 'سيصل الاقتراح باسم:' : 'Will be sent as:';
    document.getElementById('suggestText').placeholder = isAr ? 'اكتب اقتراحك هنا...' : 'Write your suggestion here...';
    document.getElementById('btnSubmitSuggest').textContent = isAr ? 'إرسال الاقتراح' : 'Submit Suggestion';
    document.getElementById('lblSuggAdminDesc').textContent = isAr ? 'اقتراحات الموظفين — تظهر هنا فقط ولا يراها أحد غيرك:' : "Employee suggestions — visible only here, no one else can see them:";

    document.getElementById('hContribute').textContent = isAr ? '📚 ساهم بحل' : '📚 Contribute a Fix';
    document.getElementById('lblContribDesc').textContent = isAr ? 'واجهت موقف ما إلو سكريبت جاهز وحليته بنفسك؟ شاركه هون — الأدمن بيراجعه وممكن يضيفه للمكتبة الرسمية.' : "Ran into a situation without a ready script and solved it yourself? Share it here — an admin reviews it and may add it to the official library.";
    document.getElementById('lblContribCat').textContent = isAr ? 'التصنيف:' : 'Category:';
    document.getElementById('contributeTitle').placeholder = isAr ? 'عنوان السكريبت...' : 'Script title...';
    document.getElementById('contributeText').placeholder = isAr ? 'نص الحل...' : 'The solution text...';
    document.getElementById('btnSubmitContribute').textContent = isAr ? 'إرسال للمراجعة' : 'Submit for Review';
    document.getElementById('lblMyContribs').textContent = isAr ? 'مساهماتي:' : 'My Contributions:';
    document.getElementById('lblContribAdminDesc').textContent = isAr ? 'مساهمات الموظفين بحلول جاهزة — راجعها ثم انشرها بمكتبة السكريبتات أو ارفضها:' : 'Employee-contributed solutions — review, then publish to the Script Library or reject:';
    renderContributePanel();

    document.getElementById('hAdminPortal').textContent = isAr ? '⚙️ بوابة إدارة النظام' : '⚙️ Admin Management Portal';
    document.getElementById('lblAdminPass').textContent = isAr ? 'ما عندك صلاحية الوصول لهذه اللوحة.' : "You don't have access to this panel.";
    updateAdminRoleLabel();

    document.getElementById('btnTab1').textContent = isAr ? '+ إدارة السكريبتات' : '+ Manage Scripts';
    document.getElementById('btnTab2').textContent = isAr ? '🏷️ التبويبات' : '🏷️ Categories';
    document.getElementById('btnTab3').textContent = isAr ? '📌 القوائم الجانبية' : '📌 Side Panels';
    document.getElementById('btnTab4').textContent = isAr ? '🔔 نيو ابديت' : '🔔 New Update';
    document.getElementById('btnTab5').textContent = isAr ? '💡 الاقتراحات' : '💡 Suggestions';
    document.getElementById('btnTab6').textContent = isAr ? '👥 المستخدمون المتصلون' : '👥 Online Users';
    document.getElementById('btnTab7').textContent = isAr ? '🎓 مركز التدريب' : '🎓 Training Center';
    document.getElementById('lblPresenceOnline').textContent = isAr ? 'متصل الآن' : 'Online now';
    document.getElementById('lblPresenceTotal').textContent = isAr ? 'إجمالي المستخدمين المسجّلين' : 'Total tracked users';
    document.getElementById('presenceColUser').textContent = isAr ? 'المستخدم' : 'User';
    document.getElementById('presenceColStatus').textContent = isAr ? 'الحالة' : 'Status';
    document.getElementById('presenceColLastActive').textContent = isAr ? 'آخر نشاط' : 'Last Active';
    document.getElementById('presenceColLoginTime').textContent = isAr ? 'وقت تسجيل الدخول' : 'Login Time';
    document.getElementById('presenceEmptyText').textContent = isAr ? 'لا يوجد مستخدمون بعد.' : 'No users yet.';
    if (PRESENCE_USERS.length) renderPresenceList();

    document.getElementById('bbHomeLabel').textContent = isAr ? 'الرئيسية' : 'Home';
    document.getElementById('swUpdateText').textContent = isAr ? 'في تحديث جديد للموقع' : 'A new version is available';
    document.getElementById('swUpdateBtn').textContent = isAr ? 'تحديث' : 'Refresh';
    document.getElementById('techPageTitle').textContent = isAr ? '🛠️ مشاكل تقنية' : '🛠️ Technical Issues';
    document.getElementById('techLiveLabel').textContent = isAr ? 'سجل توثيق' : 'Log';
    document.getElementById('techFormHeadTitle').textContent = isAr ? 'تسجيل مشكلة' : 'Log an Issue';
    document.getElementById('techFormHeadSub').textContent = isAr ? 'اختر الرقم ثم نوع المشكلة' : 'Pick the number, then the issue type';
    document.getElementById('techNumLabel').textContent = isAr ? 'أدخل رقم البوليصة أو رقم المكالمة' : 'Enter the Waybill number or call number';
    document.getElementById('techNumberInput').placeholder = '';
    document.getElementById('techAttachBtn').textContent = isAr ? 'إرفاق' : 'Attach';
    document.getElementById('techAttachedLabel').childNodes[0].textContent = isAr ? 'الرقم المرفق: ' : 'Attached number: ';
    document.getElementById('techChangeNumBtn').textContent = isAr ? 'تغيير الرقم' : 'Change number';
    document.getElementById('techOptionsLabel').textContent = isAr ? 'اختر نوع المشكلة:' : 'Select the type of issue:';
    document.querySelector('#techOptAudio span:not(.opt-icon)').textContent = isAr ? 'الصوت بالمكالمة مشوش' : 'Audio is unclear';
    document.querySelector('#techOptClosed span:not(.opt-icon)').textContent = isAr ? 'تم إغلاق المكالمة' : 'Call got disconnected';
    document.querySelector('#techOptDelay span:not(.opt-icon)').textContent = isAr ? 'تأخير في المكالمة' : 'Delay in the call';
    document.getElementById('techSheetTitle').textContent = isAr ? '📋 سجل المشاكل التقنية' : '📋 Technical Issues Log';
    document.getElementById('techRecordSearch').placeholder = isAr ? 'ابحث بالرقم أو الموظف أو نوع المشكلة...' : 'Search by number, employee, or issue type...';
    document.getElementById('techColNum').textContent = isAr ? 'الرقم' : 'Number';
    document.getElementById('techColIssue').textContent = isAr ? 'المشكلة' : 'Issue';
    document.getElementById('techColEmail').textContent = isAr ? 'الموظف' : 'Employee';
    document.getElementById('techColTime').textContent = isAr ? 'الوقت' : 'Time';
    document.getElementById('techEmptyTitle').textContent = isAr ? 'لا توجد مشاكل مسجلة بعد' : 'No issues logged yet';
    document.getElementById('techEmptySub').textContent = isAr ? 'ستظهر المشاكل هنا فور تسجيلها' : 'Logged issues will appear here';
    document.getElementById('techExportBtnLabel').textContent = isAr ? 'تصدير' : 'Export';
    document.getElementById('techStatTotalLabel').textContent = isAr ? 'إجمالي المسجل' : 'Total logged';
    document.getElementById('techStatTodayLabel').textContent = isAr ? 'اليوم' : 'Today';
    document.getElementById('techStatTopLabel').textContent = isAr ? 'الأكثر تكراراً' : 'Most common';
    if (TECH_ISSUES.length) renderTechSheet();

    // Command Center hero
    const heroText = {
      cmdEyebrowText: ['نوفا · كل أدواتك أمامك', 'Nova · All your tools, right here'],
      cmdScriptsTitle: ['مكتبة السكريبتات', 'Script Library'],
      cmdScriptsSub: ['دور، انسخ، رد على العميل', 'Search, copy, reply to the customer'],
      cmdScriptsSearchText: ['دور بالسكريبتات...', 'Search scripts...'],
      cmdStatUsageLbl: ['إجمالي الاستخدام', 'Total uses'],
      cmdStatCountLbl: ['سكريبت', 'scripts'],
      cmdTechTitle: ['مشاكل تقنية', 'Technical Issues'],
      cmdTechSub: ['سجل توثيق المكالمات', 'A log of call issues'],
      cmdTrainingTitle: ['مركز التدريب', 'Training Center'],
      cmdMentorTitle: ['الرعاية والتدريب', 'Mentorship'],
      cmdUpdatesTitle: ['التحديثات', 'Updates'],
      cmdUpdatesSub: ['اليوم', 'Today'],
    };
    Object.keys(heroText).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = isAr ? heroText[id][0] : heroText[id][1];
    });
    refreshHeroCounts();

    document.getElementById('trainingPageTitle').textContent = isAr ? 'مركز التدريب' : 'Training Center';
    document.getElementById('trainingPageSub').textContent = isAr ? 'دليلك للتعامل مع جميع مشاكل العملاء خطوة بخطوة' : 'Your guide to handling every customer issue step by step';
    document.getElementById('trainingSearchInput').placeholder = isAr ? 'ابحث عن سيناريو تدريبي...' : 'Search training scenarios...';
    document.getElementById('trainingSectionLabel').textContent = isAr ? 'ابدأ من هنا' : 'Get Started';
    document.getElementById('trainingFooterQ').textContent = isAr ? 'عندك سؤال أو اقتراح ما لقيت جوابه هون؟' : "Got a question or suggestion you couldn't find here?";
    document.getElementById('trainingFooterBtnLabel').textContent = isAr ? 'أرسل اقتراح' : 'Send a suggestion';
    document.getElementById('trainingTreeBackLabel').textContent = isAr ? 'رجوع لكل المشاكل' : 'Back to all issues';
    if (document.getElementById('trainingPage').classList.contains('open')) {
      if (currentTrainingProblem) {
        renderTrainingTreeHead();
        renderTrainingStage();
      } else {
        renderTrainingGrid();
      }
    }

    document.getElementById('breaksMenuBtnText').textContent = isAr ? 'جدول البريكات' : 'Break Schedule';
    document.getElementById('breaksNoticeText').textContent = isAr
      ? 'رح توصلك رسالة تنبيه بصوت عند وصول موعد أي بريك من بريكاتك.'
      : "You'll get a sound alert the moment any of your breaks starts.";
    document.getElementById('breaksAddLabel').textContent = isAr
      ? 'اختر الموظفين المداومين اليوم، ثم دوس إضافة — تقدر تحدد أكثر من موظف مرة وحدة:'
      : "Pick today's employees on shift, then click add — you can select more than one at once:";
    document.getElementById('breaksTodayLabel').textContent = isAr ? '👥 جدول اليوم' : "👥 Today's Schedule";
    document.getElementById('breaksEditToggleLabel').textContent = breaksEditMode ? (isAr ? 'تم' : 'Done') : (isAr ? 'تعديل' : 'Edit');
    document.getElementById('breaksEditHint').textContent = isAr
      ? 'اختر اسم، بعدين اختر اسم تاني عشان تبدلهم بمكانهم'
      : 'Pick a name, then pick another to swap their places';
    document.getElementById('breaksIncomingLabel').textContent = isAr ? '📥 طلبات سواب واردة' : '📥 Incoming Swap Requests';
    document.getElementById('breaksOutgoingLabel').textContent = isAr ? '📤 طلباتي المرسلة' : '📤 My Sent Requests';
    document.getElementById('breakSwapTitle').textContent = isAr ? 'طلب سواب بريك' : 'Request a Break Swap';
    document.getElementById('breakSwapMySlotLabel').textContent = isAr ? 'بريكك اللي بدك تبدله' : 'Your break to swap';
    document.getElementById('breakSwapColleagueLabel').textContent = isAr ? 'الزميل' : 'Colleague';
    document.getElementById('breakSwapTargetLabel').textContent = isAr ? 'بريكه اللي بدك تاخذه' : "Which of their breaks you want";
    document.getElementById('breakSwapCancel').textContent = isAr ? 'إلغاء' : 'Cancel';
    document.getElementById('breakSwapSend').textContent = isAr ? 'إرسال الطلب' : 'Send Request';
    if (document.getElementById('breaksPage').classList.contains('open')) renderBreaksPage();

    updateThemeIcon();
  }

  function updateThemeIcon() {
    const isDark = document.body.classList.contains('dark-mode');
    const skyCheckbox = document.getElementById('skyThemeCheckbox');
    if (skyCheckbox) skyCheckbox.checked = isDark;
  }

  function toggleTheme() {
    // Flipping body.dark-mode recolors every themed element on the page at once;
    // with each one carrying its own transition, the browser paints them across
    // several frames instead of together, showing as a visible top-to-bottom
    // split. Suspend all transitions for one frame so the switch lands instantly.
    document.documentElement.classList.add('theme-switching');
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('fajer_dark_mode', document.body.classList.contains('dark-mode'));
    updateThemeIcon();
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        document.documentElement.classList.remove('theme-switching');
      });
    });
  }

  if (localStorage.getItem('fajer_dark_mode') !== 'false') {
    document.body.classList.add('dark-mode');
  }
  updateThemeIcon();

  // ====== Orbit-field animated background: drifting particles with proximity links ======
  // Each canvas only draws while its page is actually the one showing — a page nobody has
  // opened yet (or one the user just navigated away from) costs zero CPU instead of running forever.
  const orbitControllers = {};
  function initOrbitField(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const colors = ['#0B84FF', '#14B8A6', '#10B981'];
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    let W, H, points = [];
    let seeded = false;
    let running = false;

    function resize() {
      W = canvas.clientWidth;
      H = canvas.clientHeight;
      canvas.width = W * DPR;
      canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }
    function seed() {
      resize();
      const count = Math.round((W * H) / 16000);
      points = [];
      for (let i = 0; i < count; i++) {
        points.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.15, vy: (Math.random() - 0.5) * 0.15,
          r: 1 + Math.random() * 1.5,
          c: colors[i % colors.length]
        });
      }
      seeded = true;
    }
    function step() {
      if (!running) return;
      // A side panel or the admin modal opening pauses the hero's CSS animations
      // (via the cmd-hero-paused body class) but that never touched this canvas -
      // it kept redrawing every single frame underneath the panel's dimmed
      // overlay the whole time the panel stayed open, for no visible benefit
      // (the overlay hides it anyway). Skip the actual draw work while paused;
      // keep the rAF loop alive so it resumes instantly once unpaused.
      if (document.body.classList.contains('cmd-hero-paused')) {
        requestAnimationFrame(step);
        return;
      }
      ctx.clearRect(0, 0, W, H);
      for (const p of points) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }
      // This inner loop runs once per pair of particles, every single frame
      // (~8,400 pairs/frame at the default ~130-particle count on a full HD
      // screen) - it was the single hottest spot in the whole app, so every
      // operation inside it is deliberately as cheap as possible: bail out on
      // a plain subtraction before ever touching Math.sqrt (only needed once
      // per qualifying pair, not per candidate pair), and reuse one strokeStyle
      // string on the rare frame where nothing is close enough to connect.
      const maxDist = 120, maxDistSq = maxDist * maxDist;
      for (let i = 0; i < points.length; i++) {
        const a = points[i];
        for (let j = i + 1; j < points.length; j++) {
          const b = points[j];
          const dx = a.x - b.x;
          if (dx > maxDist || dx < -maxDist) continue;
          const dy = a.y - b.y;
          if (dy > maxDist || dy < -maxDist) continue;
          const distSq = dx * dx + dy * dy;
          if (distSq < maxDistSq) {
            const dist = Math.sqrt(distSq);
            ctx.strokeStyle = `rgba(20,184,166,${0.16 * (1 - dist / maxDist)})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      for (const p of points) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = p.c;
        ctx.globalAlpha = 0.75;
        ctx.fill();
        ctx.globalAlpha = 1;
      }
      requestAnimationFrame(step);
    }
    window.addEventListener('resize', () => { if (seeded) seed(); });

    orbitControllers[canvasId] = {
      start() {
        if (running) return;
        if (!seeded) seed();
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        running = true;
        requestAnimationFrame(step);
      },
      stop() { running = false; }
    };
  }
  ['orbitCanvasHome', 'orbitCanvasTech', 'orbitCanvasTraining'].forEach(initOrbitField);
  function pauseAllOrbits() { Object.values(orbitControllers).forEach(c => c.stop()); }
  orbitControllers.orbitCanvasHome.start();

  // The Command Center hero keeps its animations running even while a full-page
  // overlay (Tech Issues, Training, Mentorship, Updates) is open on top of it, since
  // those slide in with transform/opacity rather than unmounting the hero. Pause them
  // while any such page is open so the browser isn't animating an invisible section.
  // Reference-counted (not a plain toggle) because a side panel (General Info,
  // Suggest, ...) can now also request a pause while it's opened from *within* an
  // already-paused full-page overlay (e.g. the Training page's "suggest" footer
  // button) - closing just the panel must not wake the hero back up under a page
  // that's still open behind it.
  let cmdHeroPauseCount = 0;
  function pauseCmdHero() {
    cmdHeroPauseCount++;
    document.body.classList.add('cmd-hero-paused');
  }
  function resumeCmdHero() {
    cmdHeroPauseCount = Math.max(0, cmdHeroPauseCount - 1);
    if (cmdHeroPauseCount === 0) document.body.classList.remove('cmd-hero-paused');
  }

  function openScriptsPage() {
    closePanels();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTechPage();
    closeTrainingPage();
    closeBreaksPage();
    document.getElementById('scriptsPage').classList.add('open');
    pauseAllOrbits();
    pauseCmdHero();
  }
  function closeScriptsPage() {
    document.getElementById('scriptsPage').classList.remove('open');
    resumeCmdHero();
    orbitControllers.orbitCanvasHome.start();
  }

  function goToHeroSection(key) {
    if (key === 'tech') { openTechPage(); return; }
    if (key === 'training') { openTrainingPage(); return; }
    if (key === 'updates') { openUpdatesPage(); return; }
    if (key === 'mentorship') { openMentorshipPage(); return; }
    openScriptsPage();
  }

  // Keeps the command-center hero's cards in sync with the real data.
  function refreshHeroCounts() {
    renderCommandHero();
    updateMentorBadge();
  }

  // A handful of recent technical issues for the hero's preview card. TECH_ISSUES itself
  // is only loaded when the Tech page opens, so this is a small one-off fetch, cached and
  // only ever run once per session.
  let cmdTechPreview = [];
  let cmdTechPreviewLoaded = false;
  async function loadCmdTechPreview() {
    if (cmdTechPreviewLoaded) return;
    cmdTechPreviewLoaded = true;
    try {
      const { data, error } = await sb.from('technical_issues').select('*').order('id', { ascending: false }).limit(3);
      if (!error) {
        cmdTechPreview = (data || []).map(r => ({ phoneNumber: r.phone_number, issueType: r.issue_type }));
        renderCommandHero();
      }
    } catch (e) { /* best-effort preview only */ }
  }

  // Populates the Command Center hero from real data — no fabricated stats: every number
  // shown here is derived straight from what's actually loaded.
  function renderCommandHero() {
    if (!document.getElementById('cmdScriptsCard')) return;
    const isAr = currentLang === 'ar';

    // Scripts panel: real categories with live counts, top-used scripts, real totals.
    const rail = document.getElementById('cmdRail');
    if (rail) {
      rail.innerHTML = CATEGORIES.map((c, i) => {
        const count = SCRIPTS.filter(s => s.cat === c.key).length;
        const label = isAr ? c.labelAr : c.label;
        const color = safeColor(c.color) || '#0B84FF';
        return `<button type="button" class="cmd-rail-item${i === 0 ? ' on' : ''}" data-cat="${escapeHtml(c.key)}">
          <span class="sw" style="background:color-mix(in srgb, ${color} 18%, transparent);"><i style="background:${color};"></i></span>
          <span class="tx"><span class="a">${escapeHtml(label || c.key)}</span><span class="b">${count} ${isAr ? 'سكريبت' : (count === 1 ? 'script' : 'scripts')}</span></span>
        </button>`;
      }).join('');
    }

    const topScriptsEl = document.getElementById('cmdTopScripts');
    if (topScriptsEl) {
      const top = [...SCRIPTS].sort((a, b) => (b.usageCount || 0) - (a.usageCount || 0)).slice(0, 3);
      topScriptsEl.innerHTML = top.map((s, i) => {
        const cat = CATEGORIES.find(c => c.key === s.cat);
        const color = safeColor(cat ? cat.color : null) || '#0B84FF';
        const label = cat ? (isAr ? cat.labelAr : cat.label) : s.cat;
        const title = (isAr && s.titleAr) ? s.titleAr : (s.title || s.titleAr || '');
        return `<div class="cmd-sc-row">
          <span class="n mono">0${i + 1}</span>
          <span class="t">${escapeHtml(title)}</span>
          <span class="tag" style="background:color-mix(in srgb, ${color} 20%, transparent); color:${color};">${escapeHtml(label || '')}</span>
        </div>`;
      }).join('');
    }
    const totalUsage = SCRIPTS.reduce((sum, s) => sum + (s.usageCount || 0), 0);
    const statUsage = document.getElementById('cmdStatUsage');
    const statCount = document.getElementById('cmdStatCount');
    if (statUsage) statUsage.textContent = totalUsage;
    if (statCount) statCount.textContent = SCRIPTS.length;

    // Tech Issues satellite: a real handful of recent rows (lazy-loaded, see above).
    const techRows = document.getElementById('cmdTechRows');
    if (techRows) {
      if (!cmdTechPreview.length) {
        techRows.innerHTML = `<div class="cmd-tech-empty">${isAr ? 'ما في مشاكل مسجلة بعد' : 'No issues logged yet'}</div>`;
      } else {
        const dotColor = { audio: '#0B84FF', closed: '#F0424A', delay: '#D97706' };
        const pillColor = {
          audio: { bg: 'rgba(11,132,255,.18)', fg: '#7CC4FF' },
          closed: { bg: 'rgba(240,66,74,.18)', fg: '#FF9B92' },
          delay: { bg: 'rgba(217,119,6,.2)', fg: '#FBBF24' },
        };
        techRows.innerHTML = cmdTechPreview.map(t => {
          const lbl = TECH_ISSUE_LABELS[t.issueType];
          const text = lbl ? (isAr ? lbl.ar : lbl.en) : (t.issueType || '');
          const c = pillColor[t.issueType] || pillColor.audio;
          return `<div class="cmd-tech-row">
            <span class="d" style="background:${dotColor[t.issueType] || '#0B84FF'};"></span>
            <span class="num">${escapeHtml(t.phoneNumber || '')}</span>
            <span class="pill" style="background:${c.bg}; color:${c.fg};">${escapeHtml(text)}</span>
          </div>`;
        }).join('');
      }
    }

    // Training satellite: real published-topic count, no fabricated progress bars.
    const activeTraining = TRAINING_PROBLEMS.filter(p => p.isActive);
    const trainingSub = document.getElementById('cmdTrainingSub');
    if (trainingSub) trainingSub.textContent = activeTraining.length ? `${activeTraining.length} ${isAr ? 'مواضيع' : 'topics'}` : '—';
    const trainingBody = document.getElementById('cmdTrainingBody');
    if (trainingBody) {
      if (!activeTraining.length) {
        trainingBody.innerHTML = `<div class="cmd-tech-empty">${isAr ? 'ما في مواضيع منشورة بعد' : 'No published topics yet'}</div>`;
      } else {
        trainingBody.innerHTML = `
          <div class="cmd-training-count"><b class="mono">${activeTraining.length}</b><span>${isAr ? 'سيناريو تفاعلي' : 'interactive scenarios'}</span></div>
          ${activeTraining.slice(0, 2).map(p => `<div class="cmd-training-row"><span class="ic" style="background:${safeColor(p.color) || '#0B84FF'};">${escapeHtml(p.icon || '📦')}</span><span class="t">${escapeHtml(isAr ? p.titleAr : p.title)}</span></div>`).join('')}
        `;
      }
    }

    // Mentorship strip: an honest 3-step status (request → accepted → ongoing) for the
    // user's most relevant relationship, derived straight from its real status field —
    // no fourth "first message" step, since we don't actually track that separately here.
    const mentorBody = document.getElementById('cmdMentorBody');
    if (mentorBody) {
      const mine = MENTOR_REQUESTS.filter(r => r.traineeEmail === currentUserEmail || r.mentorEmail === currentUserEmail);
      const active = mine.find(r => r.status === 'accepted') || mine.find(r => r.status === 'pending');
      if (!active) {
        mentorBody.innerHTML = `<div class="cmd-mentor-cta">
          <p>${isAr ? 'ما عندك رعاية نشطة بعد' : "You don't have an active mentorship yet"}</p>
          <span class="btn">${isAr ? 'اطلب راعي تدريب' : 'Request a mentor'}</span>
        </div>`;
      } else {
        const accepted = active.status === 'accepted';
        mentorBody.innerHTML = `
          <div class="cmd-stepper">
            <div class="cmd-step"><div class="circ" style="background:linear-gradient(150deg,#10B981,#22D3EE); color:#fff;">✓</div><div class="lbl"><b>${isAr ? 'الطلب' : 'Request'}</b>${isAr ? 'أُرسل' : 'Sent'}</div></div>
            <div class="cmd-step-link done"></div>
            <div class="cmd-step"><div class="circ" style="background:${accepted ? 'linear-gradient(150deg,#10B981,#22D3EE)' : 'linear-gradient(150deg,#0B84FF,#22D3EE)'}; color:#fff;${accepted ? '' : ' box-shadow:0 0 0 4px rgba(11,132,255,.24);'}">${accepted ? '✓' : '●'}</div><div class="lbl"><b>${isAr ? 'القبول' : 'Accepted'}</b>${accepted ? (isAr ? 'وافق الراعي' : 'Mentor accepted') : (isAr ? 'بانتظار الرد' : 'Awaiting reply')}</div></div>
            <div class="cmd-step-link${accepted ? ' done' : ''}"></div>
            <div class="cmd-step"><div class="circ" style="${accepted ? 'background:linear-gradient(150deg,#0B84FF,#22D3EE); box-shadow:0 0 0 4px rgba(11,132,255,.24);' : 'background:rgba(255,255,255,.1); border:1px solid rgba(255,255,255,.16);'} color:#fff;">${accepted ? '●' : '3'}</div><div class="lbl"><b>${isAr ? 'متابعة' : 'Ongoing'}</b>${accepted ? (isAr ? 'محادثة نشطة' : 'Active chat') : (isAr ? 'قريباً' : 'Coming up')}</div></div>
          </div>
        `;
      }
    }

    // Updates satellite: real recent updates, unseen ones flagged exactly like the badge.
    const updRows = document.getElementById('cmdUpdatesRows');
    if (updRows) {
      const lastSeen = parseInt(localStorage.getItem('fajer_updates_seen_v2') || '0', 10);
      const recent = [...UPDATES].sort((a, b) => b.id - a.id).slice(0, 2);
      if (!recent.length) {
        updRows.innerHTML = `<div class="cmd-upd-empty">${isAr ? 'ما في تحديثات بعد' : 'No updates yet'}</div>`;
      } else {
        updRows.innerHTML = recent.map(u => `
          <div class="cmd-upd-row">
            <span class="bell"${u.id > lastSeen ? '' : ' style="background:rgba(255,255,255,.2);"'}></span>
            <span class="skel">${escapeHtml(u.text)}</span>
            ${u.id > lastSeen ? `<span class="new">${isAr ? 'جديد' : 'New'}</span>` : ''}
          </div>
        `).join('');
      }
    }

  }

  let dashTipItem = null;
  function pickDashTip() {
    dashTipItem = CRITICAL_ITEMS.length ? CRITICAL_ITEMS[Math.floor(Math.random() * CRITICAL_ITEMS.length)] : null;
  }

  function renderDashTip() {
    const wrap = document.getElementById('dashTip');
    if (!wrap) return;
    if (!dashTipItem) { wrap.style.display = 'none'; wrap.innerHTML = ''; return; }
    const isAr = currentLang === 'ar';
    const label = isAr ? '⚠️ تذكير' : '⚠️ Reminder';
    const text = (isAr && dashTipItem.textAr) ? dashTipItem.textAr : dashTipItem.text;
    wrap.style.display = 'flex';
    wrap.innerHTML = `<span class="dash-tip-label">${escapeHtml(label)}</span><span class="dash-tip-text">${escapeHtml(text)}</span>`;
  }

  function render() {
    if(isAdmin) document.body.classList.add('admin-mode');
    else document.body.classList.remove('admin-mode');

    if(isAdmin && adminRole === 'limited') document.body.classList.add('admin-limited');
    else document.body.classList.remove('admin-limited');

    const isAr = currentLang === 'ar';
    renderSequence = 0;
    
    // Render Top Tabs
    const tabsEl = document.getElementById('tabs');
    const allText = isAr ? 'جميع السكريبتات' : 'All Scripts';
    tabsEl.innerHTML = `<div class="tab ${activeCat===null?'active':''}" data-cat="">${allText}</div>` +
      CATEGORIES.map(c => {
        const catLabel = (isAr && c.labelAr) ? c.labelAr : c.label;
        return `<div class="tab ${activeCat===c.key?'active':''}" data-cat="${c.key}"><span class="dot" style="background:${safeColor(c.color)}"></span>${escapeHtml(catLabel)}</div>`;
      }).join('');

    const q = document.getElementById('searchInput').value.toLowerCase();
    const content = document.getElementById('content');
    content.innerHTML = '';
    let visibleCount = 0;

    CATEGORIES.forEach((cat, idx) => {
      if(activeCat && activeCat !== cat.key) return;
      
      const items = SCRIPTS.filter(s => {
        if (s.cat !== cat.key) return false;
        if (!q) return true;
        const searchPool = (s.title + (s.titleAr||'') + s.text + (s.textAr||'')).toLowerCase();
        return searchPool.includes(q);
      });

      if(!items.length) return;
      visibleCount += items.length;

      const catLabel = (isAr && cat.labelAr) ? cat.labelAr : cat.label;
      const sec = document.createElement('div');
      sec.className = 'section';
      sec.innerHTML = `<div class="section-head"><span class="idx" style="background:${safeColor(cat.color)}">${idx+1}</span><h2>${escapeHtml(catLabel)}</h2><span class="section-count">${items.length} ${isAr ? 'سكريبت' : 'scripts'}</span></div><div class="grid"></div>`;
      const grid = sec.querySelector('.grid');
      
      items.forEach(s => {
        const titleToDisplay = (isAr && s.titleAr) ? s.titleAr : s.title;
        const textToDisplay = (isAr && s.textAr) ? s.textAr : s.text;
        grid.appendChild(createCard(titleToDisplay, textToDisplay, cat.color, catLabel, SCRIPTS.indexOf(s), s.usageCount || 0));
      });
      content.appendChild(sec);
    });

    // Render FollowUp
    const followupGrid = document.getElementById('followupGrid');
    followupGrid.innerHTML = '';
    const followBadge = isAr ? 'متابعة' : 'Follow Up';
    FOLLOWUP.filter(f => {
      if(!q) return true;
      return (f.title + (f.titleAr||'') + f.text + (f.textAr||'')).toLowerCase().includes(q);
    }).forEach(f => {
      visibleCount += 1;
      const titleToDisplay = (isAr && f.titleAr) ? f.titleAr : f.title;
      const textToDisplay = (isAr && f.textAr) ? f.textAr : f.text;
      followupGrid.appendChild(createCard(titleToDisplay, textToDisplay, '#334155', followBadge, -1, f.usageCount || 0, f));
    });

    const countEl = document.getElementById('scriptCount');
    const countWrap = countEl.closest('.library-count');
    countEl.textContent = visibleCount;
    if (previousVisibleCount !== -1 && previousVisibleCount !== visibleCount) {
      countWrap.classList.remove('updated');
      requestAnimationFrame(() => {
        countWrap.classList.add('updated');
        setTimeout(() => countWrap.classList.remove('updated'), 260);
      });
    }
    previousVisibleCount = visibleCount;
    if (!visibleCount) {
      content.innerHTML = `<div class="empty-state"><span class="empty-icon">🔍</span><strong>${isAr ? 'لا توجد نتائج مطابقة' : 'No matching scripts'}</strong><div style="margin-top:6px;font-size:12px">${isAr ? 'جرّب كلمة بحث أخرى أو اختر جميع السكريبتات.' : 'Try another search term or select All Scripts.'}</div></div>`;
    }

    renderSidePanels();
    updateAdminDropdowns();
    renderDashTip();
  }

  function renderSidePanels() {
    const isAr = currentLang === 'ar';
    document.getElementById('generalList').innerHTML = GENERAL_INFO.map(info => {
      const label = (isAr && info.labelAr) ? info.labelAr : info.label;
      const val = (isAr && info.valAr) ? info.valAr : info.val;
      return `<div class="info-card"><span class="label">${escapeHtml(label)}</span><span class="val">${escapeHtml(val)}</span></div>`;
    }).join('');

    document.getElementById('criticalList').innerHTML = CRITICAL_ITEMS.map((m, i) => {
      const text = (isAr && m.textAr) ? m.textAr : m.text;
      return `<p style="padding:8px; background:rgba(185,28,28,0.1); border-inline-start:3px solid #B91C1C; margin-bottom:6px; font-size:12.5px;"><b>${i+1}.</b> ${escapeHtml(text)}</p>`;
    }).join('');

    document.getElementById('etiquetteList').innerHTML = ETIQUETTE_ITEMS.map(s => {
      const text = (isAr && s.textAr) ? s.textAr : s.text;
      return `<p style="padding:8px; background:rgba(20,91,140,0.1); border-inline-start:3px solid #145b8c; margin-bottom:6px; font-size:13px;">${escapeHtml(text)}</p>`;
    }).join('');

    updateNotificationBadge();
  }

  // ===================== Updates page (full page, replaces the old cramped side-panel) =====================
  let updatesUnseenAtOpen = new Set();
  let currentUpdatesFilter = 'all'; // 'all' | 'week' | 'archive'

  // Groups a sorted (newest-first) list of updates into day buckets ("Today", "Yesterday",
  // then the calendar date) and renders each bucket as a labeled section of the timeline.
  function renderUpdatesTimeline(updates, isAr) {
    const dayLabel = (ts) => {
      const d = new Date(ts);
      const now = new Date();
      const startOfDay = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
      const diffDays = Math.round((startOfDay(now) - startOfDay(d)) / (24 * 60 * 60 * 1000));
      if (diffDays === 0) return isAr ? 'اليوم' : 'Today';
      if (diffDays === 1) return isAr ? 'أمس' : 'Yesterday';
      return d.toLocaleDateString(isAr ? 'ar' : 'en', { day: 'numeric', month: 'long' });
    };
    let html = '';
    let lastLabel = null;
    updates.forEach(u => {
      const label = dayLabel(u.createdAt);
      if (label !== lastLabel) {
        html += `<div class="tl-group-label">${escapeHtml(label)}</div>`;
        lastLabel = label;
      }
      const timeStr = new Date(u.createdAt).toLocaleTimeString(isAr ? 'ar-EG' : 'en-US', { hour: '2-digit', minute: '2-digit' });
      const isNew = updatesUnseenAtOpen.has(u.id);
      const chip = isNew ? `<span class="update-new-chip">${isAr ? 'جديد' : 'New'}</span>` : '';
      const image = u.imageUrl ? `<img src="${escapeHtml(u.imageUrl)}" class="update-image" alt="" loading="lazy">` : '';
      const textEl = u.text ? `<div class="update-text">${escapeHtml(u.text)}</div>` : '';
      html += `<div class="tl-item"><div class="update-card${isNew ? ' is-new' : ''}"><div class="update-top"><span class="update-date">${timeStr}</span>${chip}</div>${image}${textEl}</div></div>`;
    });
    return html;
  }

  function setUpdatesFilter(filter) {
    currentUpdatesFilter = filter;
    document.querySelectorAll('#updatesFilterChips .chip').forEach(el => {
      el.classList.toggle('on', el.dataset.updatesFilter === filter);
    });
    renderUpdatesPage();
  }

  function renderUpdatesPage() {
    const isAr = currentLang === 'ar';
    const q = (document.getElementById('updatesSearchInput')?.value || '').toLowerCase().trim();
    const recentSection = document.getElementById('updatesRecentSection');
    const recentList = document.getElementById('updatesRecentList');
    const emptyEl = document.getElementById('updatesEmpty');
    if (!recentList) return;

    const sortedUpdates = [...UPDATES].filter(u => !q || u.text.toLowerCase().includes(q)).sort((a, b) => b.id - a.id);

    const totalEl = document.getElementById('updatesStatTotal');
    const weekEl = document.getElementById('updatesStatWeek');
    if (totalEl) totalEl.textContent = UPDATES.length;
    if (weekEl) {
      const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      weekEl.textContent = UPDATES.filter(u => u.createdAt >= weekAgo).length;
    }

    if (!UPDATES.length) {
      recentSection.style.display = 'none';
      emptyEl.style.display = 'block';
      document.getElementById('updatesEmptyTitle').textContent = isAr ? 'لا توجد تحديثات بعد' : 'No updates yet';
      document.getElementById('updatesEmptySub').textContent = isAr ? 'أي إعلان جديد رح يظهر هون' : 'New announcements will show up here';
      return;
    }

    const ARCHIVE_MS = UPDATE_ARCHIVE_DAYS * 24 * 60 * 60 * 1000;
    const weekMs = 7 * 24 * 60 * 60 * 1000;
    let filteredUpdates = sortedUpdates;
    if (currentUpdatesFilter === 'week') {
      filteredUpdates = sortedUpdates.filter(u => u.createdAt >= Date.now() - weekMs);
    } else if (currentUpdatesFilter === 'archive') {
      filteredUpdates = sortedUpdates.filter(u => u.createdAt < Date.now() - ARCHIVE_MS);
    }

    if (!filteredUpdates.length) {
      recentSection.style.display = 'none';
      emptyEl.style.display = 'block';
      document.getElementById('updatesEmptyTitle').textContent = isAr ? 'لا توجد نتائج مطابقة' : 'No matching results';
      document.getElementById('updatesEmptySub').textContent = isAr ? 'جرّب فلتر أو كلمة بحث أخرى.' : 'Try a different filter or search term.';
      return;
    }
    emptyEl.style.display = 'none';

    recentSection.style.display = 'block';
    recentList.innerHTML = renderUpdatesTimeline(filteredUpdates, isAr);
  }

  function openUpdatesPage() {
    closePanels();
    closeScriptsPage();
    closeMentorshipPage();
    closeTechPage();
    closeTrainingPage();
    closeBreaksPage();
    pauseAllOrbits();
    pauseCmdHero();

    const lastSeen = parseInt(localStorage.getItem('fajer_updates_seen_v2') || '0', 10);
    updatesUnseenAtOpen = new Set(UPDATES.filter(u => u.id > lastSeen).map(u => u.id));

    const input = document.getElementById('updatesSearchInput');
    if (input) input.value = '';
    currentUpdatesFilter = 'all';
    document.querySelectorAll('#updatesFilterChips .chip').forEach(el => {
      el.classList.toggle('on', el.dataset.updatesFilter === 'all');
    });
    renderUpdatesPage();

    const latestId = UPDATES.reduce((max, u) => Math.max(max, u.id), 0);
    localStorage.setItem('fajer_updates_seen_v2', String(latestId));
    updateNotificationBadge();
    refreshHeroCounts();

    document.getElementById('updatesPage').classList.add('open');
  }
  function closeUpdatesPage() {
    document.getElementById('updatesPage').classList.remove('open');
    resumeCmdHero();
  }

  function updateNotificationBadge() {
    const lastSeen = parseInt(localStorage.getItem('fajer_updates_seen_v2') || '0', 10);
    const unseenCount = UPDATES.filter(u => u.id > lastSeen).length;
    const label = unseenCount > 9 ? '9+' : String(unseenCount);
    const badge = document.getElementById('nvhUpdatesBadge');
    if (badge) {
      if (unseenCount > 0) {
        badge.textContent = label;
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }
    }
  }

  // ----- Shared image-attachment upload (Updates composer + mentor chat paste).
  // Screenshots straight out of the OS clipboard can be several MB, so every
  // image is downscaled/re-encoded on the client first, then uploaded into the
  // public "attachments" Storage bucket and its public URL returned. Requires
  // supabase_attachments.sql to have been applied - the bucket and image_url
  // columns don't exist until that migration runs.
  const MAX_ATTACHMENT_DIMENSION = 1600;
  const MAX_ATTACHMENT_RAW_BYTES = 20 * 1024 * 1024;
  function downscaleImageFile(file) {
    return new Promise((resolve) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const scale = Math.min(1, MAX_ATTACHMENT_DIMENSION / Math.max(img.width, img.height));
        const w = Math.max(1, Math.round(img.width * scale)), h = Math.max(1, Math.round(img.height * scale));
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        canvas.toBlob((blob) => resolve(blob || file), 'image/jpeg', 0.82);
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(file); };
      img.src = url;
    });
  }
  async function uploadAttachmentImage(file, folder) {
    if (!file || file.size > MAX_ATTACHMENT_RAW_BYTES) return null;
    const blob = await downscaleImageFile(file);
    const ext = blob.type === 'image/png' ? 'png' : (blob.type === 'image/webp' ? 'webp' : 'jpg');
    const path = `${folder}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const { error } = await sb.storage.from('attachments').upload(path, blob, { contentType: blob.type || 'image/jpeg' });
    if (error) return null;
    const { data } = sb.storage.from('attachments').getPublicUrl(path);
    return data?.publicUrl || null;
  }

  let newUpdateImageFile = null;
  function pickNewUpdateImage(file) {
    if (!file) return;
    newUpdateImageFile = file;
    const preview = document.getElementById('newUpdImagePreview');
    const wrap = document.getElementById('newUpdImagePreviewWrap');
    preview.src = URL.createObjectURL(file);
    wrap.style.display = 'block';
  }
  function clearNewUpdateImage() {
    newUpdateImageFile = null;
    document.getElementById('newUpdImageInput').value = '';
    document.getElementById('newUpdImagePreviewWrap').style.display = 'none';
  }

  // Pasting a screenshot (Ctrl/Cmd+V) straight into the update text box attaches
  // it the same as picking it via the file button - no need to save it
  // somewhere first and browse for it.
  function handleNewUpdateTextPaste(e) {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
      if (item.type && item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) pickNewUpdateImage(file);
        return;
      }
    }
  }

  async function addUpdate() {
    const isAr = currentLang === 'ar';
    const text = document.getElementById('newUpdText').value.trim();
    const imageFile = newUpdateImageFile;
    if (!text && !imageFile) return;
    const btn = document.getElementById('btnAddUpd');
    const btnLabel = btn.textContent;
    btn.disabled = true;
    btn.textContent = isAr ? 'جارٍ النشر...' : 'Publishing...';
    let imageUrl = null;
    if (imageFile) {
      imageUrl = await uploadAttachmentImage(imageFile, 'updates');
      if (!imageUrl) {
        showToast(isAr ? 'تعذّر رفع الصورة.' : 'Could not upload the image.', 'error');
        btn.disabled = false; btn.textContent = btnLabel;
        return;
      }
    }
    const { data, error } = await sb.from('updates').insert({ text, image_url: imageUrl }).select().single();
    btn.disabled = false; btn.textContent = btnLabel;
    if (error) {
      showToast(isAr ? 'تعذّر نشر التحديث.' : 'Could not publish the update.', 'error');
      return;
    }
    UPDATES.push({ id: data.id, text: data.text, imageUrl: data.image_url, createdAt: new Date(data.created_at).getTime() });
    document.getElementById('newUpdText').value = '';
    clearNewUpdateImage();
    render();
    renderAdminLists();
    showToast(isAr ? 'تم نشر التحديث! سيظهر إشعار للفريق.' : 'Update published! The team will see a notification.', 'success');
  }

  async function deleteUpdate(id) {
    if (!canDelete()) return;
    const { error } = await sb.from('updates').delete().eq('id', id);
    if (error) {
      showToast(currentLang === 'ar' ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    UPDATES = UPDATES.filter(u => u.id !== id);
    render();
    renderAdminLists();
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[ch]));
  }

  // يتأكد إن قيمة اللون صيغة hex سليمة قبل حقنها بـ style="" مباشرة، لمنع كسر الـ attribute
  function safeColor(val) {
    return /^#[0-9a-fA-F]{3,8}$/.test(String(val || '').trim()) ? val : '#334155';
  }

  // ===================== Training illustrations (isometric 3D-style icons) =====================
  function shadeHex(hex, percent) {
    const h = safeColor(hex).replace('#', '');
    const full = h.length === 3 ? h.split('').map(c => c + c).join('') : h.padEnd(6, '0');
    const num = parseInt(full.slice(0, 6), 16);
    let r = (num >> 16) & 255, g = (num >> 8) & 255, b = num & 255;
    const adjust = (c) => {
      const v = percent >= 0 ? c + (255 - c) * percent : c * (1 + percent);
      return Math.max(0, Math.min(255, Math.round(v)));
    };
    r = adjust(r); g = adjust(g); b = adjust(b);
    return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
  }

  const TRAINING_ICON_DEFS = {
    box: (l, m, d) => `<polygon points="50,14 86,32 50,50 14,32" fill="${l}"/><polygon points="14,32 50,50 50,88 14,70" fill="${m}"/><polygon points="86,32 50,50 50,88 86,70" fill="${d}"/><polygon points="50,14 68,23 50,32 32,23" fill="#fff" opacity=".22"/><rect x="60" y="46" width="18" height="13" rx="2" fill="${l}" opacity=".9"/><rect x="63" y="49" width="12" height="2.4" rx="1.2" fill="${d}" opacity=".55"/><rect x="63" y="54" width="8" height="2.4" rx="1.2" fill="${d}" opacity=".55"/>`,
    refresh: (l, m, d) => `<circle cx="50" cy="50" r="30" fill="${l}" opacity=".2"/><path d="M27 44a23 23 0 0 1 40-13" fill="none" stroke="${m}" stroke-width="9" stroke-linecap="round"/><path d="M73 56a23 23 0 0 1-40 13" fill="none" stroke="${d}" stroke-width="9" stroke-linecap="round"/><polygon points="65,22 79,26 71,38" fill="${m}"/><polygon points="35,78 21,74 29,62" fill="${d}"/>`,
    warning: (l, m, d) => `<path d="M50 12 92 84 8 84Z" fill="${d}"/><path d="M50 12 92 84 66 84 42 34Z" fill="${m}"/><rect x="45" y="38" width="10" height="24" rx="4" fill="${l}"/><circle cx="50" cy="70" r="5.5" fill="${l}"/><path d="M50 12 92 84" stroke="#fff" stroke-width="1" opacity=".2"/>`,
    card: (l, m, d) => `<rect x="10" y="28" width="80" height="50" rx="8" fill="${m}"/><rect x="10" y="28" width="80" height="16" fill="${d}"/><rect x="20" y="58" width="22" height="8" rx="3" fill="${l}"/><circle cx="72" cy="62" r="9" fill="${l}" opacity=".9"/><circle cx="64" cy="62" r="9" fill="${d}" opacity=".7"/><rect x="10" y="28" width="80" height="50" rx="8" fill="none" stroke="#fff" stroke-width="1" opacity=".15"/>`,
    pin: (l, m, d) => `<path d="M50 10C33 10 20 23 20 40c0 24 30 50 30 50s30-26 30-50c0-17-13-30-30-30Z" fill="${m}"/><path d="M50 10C33 10 20 23 20 40c0 24 30 50 30 50V10Z" fill="${d}" opacity=".35"/><circle cx="50" cy="40" r="13" fill="${l}"/><circle cx="50" cy="40" r="13" fill="none" stroke="${d}" stroke-width="2" opacity=".25"/>`,
    face: (l, m, d) => `<path d="M20 92c2-18 14-28 30-28s28 10 30 28Z" fill="${d}" opacity=".9"/><circle cx="50" cy="42" r="26" fill="${m}"/><path d="M24 38c0-14 12-24 26-24s26 10 26 24c-8-4-16-10-26-10s-18 6-26 10Z" fill="${d}"/><circle cx="40" cy="42" r="3.6" fill="${d}"/><circle cx="60" cy="42" r="3.6" fill="${d}"/><path d="M39 54c5 5 17 5 22 0" stroke="${d}" stroke-width="3.6" fill="none" stroke-linecap="round"/>`,
    headset: (l, m, d) => `<path d="M22 54a28 28 0 0 1 56 0" fill="none" stroke="${m}" stroke-width="8" stroke-linecap="round"/><rect x="14" y="52" width="15" height="24" rx="7" fill="${d}"/><rect x="71" y="52" width="15" height="24" rx="7" fill="${d}"/><rect x="17" y="55" width="9" height="18" rx="4.5" fill="${l}"/><rect x="74" y="55" width="9" height="18" rx="4.5" fill="${l}"/><path d="M29 76v3a11 11 0 0 0 11 11h7" fill="none" stroke="${m}" stroke-width="6" stroke-linecap="round"/><circle cx="49" cy="90" r="4.5" fill="${d}"/>`,
    doc: (l, m, d) => `<polygon points="26,10 64,10 78,24 78,90 26,90" fill="${m}"/><polygon points="64,10 78,24 64,24" fill="${d}"/><rect x="36" y="40" width="32" height="5" rx="2.5" fill="${l}"/><rect x="36" y="52" width="32" height="5" rx="2.5" fill="${l}"/><rect x="36" y="64" width="20" height="5" rx="2.5" fill="${l}"/><circle cx="66" cy="78" r="10" fill="${l}"/><path d="M61 78l3.5 3.5L71 74" stroke="${d}" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>`,
    clock: (l, m, d) => `<circle cx="50" cy="52" r="36" fill="${d}" opacity=".25"/><circle cx="50" cy="50" r="34" fill="${m}"/><circle cx="50" cy="50" r="26" fill="${l}"/><line x1="50" y1="50" x2="50" y2="31" stroke="${d}" stroke-width="5" stroke-linecap="round"/><line x1="50" y1="50" x2="64" y2="57" stroke="${d}" stroke-width="5" stroke-linecap="round"/><circle cx="50" cy="50" r="4.5" fill="${d}"/><circle cx="50" cy="20" r="3" fill="${d}" opacity=".5"/><circle cx="80" cy="50" r="3" fill="${d}" opacity=".5"/><circle cx="50" cy="80" r="3" fill="${d}" opacity=".5"/><circle cx="20" cy="50" r="3" fill="${d}" opacity=".5"/>`,
    check: (l, m, d) => `<path d="M36 66l-10 22 14-4 8 12 9-20" fill="${d}" opacity=".55"/><path d="M64 66l10 22-14-4-8 12-9-20" fill="${d}" opacity=".4"/><circle cx="50" cy="46" r="34" fill="${m}"/><circle cx="50" cy="46" r="34" fill="none" stroke="${d}" stroke-width="3" opacity=".3"/><path d="M34 46l11 11 21-24" fill="none" stroke="${l}" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>`,
    chat: (l, m, d) => `<path d="M62 20H24a10 10 0 0 0-10 10v20a10 10 0 0 0 10 10v14l16-14h22a10 10 0 0 0 10-10V30a10 10 0 0 0-10-10Z" fill="${d}" opacity=".35"/><path d="M76 14H32a10 10 0 0 0-10 10v22a10 10 0 0 0 10 10h4v14l18-14h22a10 10 0 0 0 10-10V24a10 10 0 0 0-10-10Z" fill="${m}"/><circle cx="44" cy="35" r="4" fill="${l}"/><circle cx="58" cy="35" r="4" fill="${l}"/><circle cx="72" cy="35" r="4" fill="${l}"/>`,
    list: (l, m, d) => `<rect x="16" y="12" width="68" height="76" rx="10" fill="${m}"/><rect x="16" y="12" width="68" height="14" rx="10" fill="${d}"/><rect x="27" y="38" width="9" height="9" rx="2.5" fill="${l}"/><path d="M29 42.5l2 2.5 4-5" stroke="${d}" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/><rect x="42" y="39" width="30" height="5" rx="2.5" fill="${l}"/><rect x="27" y="55" width="9" height="9" rx="2.5" fill="${l}"/><path d="M29 59.5l2 2.5 4-5" stroke="${d}" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/><rect x="42" y="56" width="30" height="5" rx="2.5" fill="${l}"/><rect x="27" y="72" width="9" height="9" rx="2.5" fill="${l}" opacity=".55"/><rect x="42" y="73" width="20" height="5" rx="2.5" fill="${l}" opacity=".55"/>`,
    truck: (l, m, d) => `<rect x="10" y="38" width="48" height="32" rx="4" fill="${m}"/><polygon points="58,48 80,48 90,60 90,70 58,70" fill="${d}"/><rect x="64" y="52" width="15" height="11" rx="2" fill="${l}"/><circle cx="28" cy="76" r="9" fill="${d}"/><circle cx="74" cy="76" r="9" fill="${d}"/><circle cx="28" cy="76" r="4" fill="${l}"/><circle cx="74" cy="76" r="4" fill="${l}"/><path d="M6 44h6M4 50h8M6 56h6" stroke="${d}" stroke-width="2.5" stroke-linecap="round" opacity=".4"/>`
  };
  const TRAINING_ICON_KEYS = Object.keys(TRAINING_ICON_DEFS);

  function renderTrainingIllustration(iconKey, colorHex, sizeClass) {
    const base = safeColor(colorHex);
    const light = shadeHex(base, 0.55);
    const mid = base;
    const dark = shadeHex(base, -0.28);
    const bgLight = shadeHex(base, 0.82);
    const bgMid = shadeHex(base, 0.6);
    const def = TRAINING_ICON_DEFS[iconKey];
    if (!def) return null;
    return `<div class="training-illus ${sizeClass || ''}" style="background:radial-gradient(120% 130% at 28% 15%, ${bgLight}, ${bgMid} 75%);">
      <span class="training-illus-glow"></span>
      <span class="training-illus-shadow"></span>
      <svg class="training-illus-svg" viewBox="0 0 100 100">${def(light, mid, dark)}</svg>
    </div>`;
  }

  function showToast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: '✅', error: '⚠️', info: '💬' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 300);
    }, 3200);
  }

  // Despite the name, this never actually checked the date — it ran the full splash
  // animation (a fixed 1.2s hold + 550ms fade, ~1.75s total) on every single login and
  // every page reload while already signed in, all day, every day. That's a mandatory
  // delay on top of however fast the real data actually loaded, on every boot. Now it
  // really is once-per-day: any boot after the first one today skips straight past it.
  function checkFirstVisitToday() {
    const splash = document.getElementById('splashOverlay');
    if (!splash) return;
    const today = new Date().toISOString().slice(0, 10);
    let lastShown = null;
    try { lastShown = localStorage.getItem('novaSplashLastShown'); } catch (e) { /* storage blocked — fall back to showing it */ }
    if (lastShown === today) {
      splash.remove();
      return;
    }
    try { localStorage.setItem('novaSplashLastShown', today); } catch (e) { /* best-effort only */ }
    setTimeout(() => {
      splash.classList.add('hide');
      setTimeout(() => splash.remove(), 550);
    }, 1200);
  }

  function showSkeleton() {
    const content = document.getElementById('content');
    if (!content) return;
    let cards = '';
    for (let i = 0; i < 6; i++) {
      cards += `<div class="skeleton-card">
        <div class="skeleton-line w-40" style="height:16px;"></div>
        <div class="skeleton-line w-90" style="margin-top:14px;"></div>
        <div class="skeleton-line w-70"></div>
        <div class="skeleton-line w-60"></div>
      </div>`;
    }
    content.innerHTML = `<div class="skeleton-grid">${cards}</div>`;
  }

  function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function (e) {
      const tag = (e.target && e.target.tagName || '').toLowerCase();
      const isTyping = tag === 'input' || tag === 'textarea' || (e.target && e.target.isContentEditable);
      if (e.key === '/' && !isTyping) {
        e.preventDefault();
        const input = document.getElementById('searchInput');
        if (input) input.focus();
      }
      if (e.key === 'Escape') {
        closeImageLightbox();
        closePanels();
        closeAdminModal();
        closeTechPage();
        closeTrainingPage();
        closeUpdatesPage();
        closeMentorshipPage();
      }
    });
  }

  async function submitSuggestion() {
    const isAr = currentLang === 'ar';
    const name = currentUserEmail;
    const text = document.getElementById('suggestText').value.trim();
    if (!name) {
      showToast(isAr ? 'تعذّر التعرف على المستخدم، الرجاء تسجيل الدخول مجدداً.' : 'Could not identify the user, please sign in again.', 'error');
      return;
    }
    if (!text) {
      showToast(isAr ? 'يرجى كتابة الاقتراح.' : 'Please enter your suggestion.', 'error');
      return;
    }
    const { error } = await sb.from('suggestions').insert({ name, text });
    if (error) {
      showToast(isAr ? 'تعذّر إرسال الاقتراح.' : 'Could not send the suggestion.', 'error');
      return;
    }
    document.getElementById('suggestText').value = '';
    if (isAdmin) {
      const sugRes = await sb.from('suggestions').select('*').order('id', { ascending: false });
      SUGGESTIONS = sugRes.error ? SUGGESTIONS : (sugRes.data || []).map(s => ({ id: s.id, name: s.name, text: s.text, createdAt: new Date(s.created_at).getTime() }));
      renderAdminLists();
    }
    closePanels();
    showToast(isAr ? 'شكراً لك! تم إرسال اقتراحك بنجاح.' : 'Thank you! Your suggestion has been sent.', 'success');
  }

  async function deleteSuggestion(id) {
    if (!canDelete()) return;
    const { error } = await sb.from('suggestions').delete().eq('id', id);
    if (error) {
      showToast(currentLang === 'ar' ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    SUGGESTIONS = SUGGESTIONS.filter(s => s.id !== id);
    renderAdminLists();
  }

  // ===================== Contribute a Fix (crowd-sourced script library) =====================
  function renderContributePanel() {
    const isAr = currentLang === 'ar';
    const sel = document.getElementById('contributeCat');
    if (sel) {
      sel.innerHTML = CATEGORIES.map(c => `<option value="${c.key}">${escapeHtml((isAr && c.labelAr) ? c.labelAr : c.label)}</option>`).join('');
    }
    const list = document.getElementById('myContributionsList');
    if (!list) return;
    const statusLabel = {
      pending: [isAr ? 'قيد المراجعة' : 'Pending', '#D97706'],
      approved: [isAr ? 'اتنشرت' : 'Published', '#10B981'],
      rejected: [isAr ? 'مرفوض' : 'Rejected', '#B91C1C']
    };
    const mine = SCRIPT_SUBMISSIONS.filter(s => s.submittedBy === currentUserEmail).sort((a, b) => b.id - a.id);
    list.innerHTML = mine.length ? mine.map(s => {
      const [label, color] = statusLabel[s.status] || statusLabel.pending;
      const title = (isAr && s.titleAr) ? s.titleAr : (s.title || s.titleAr);
      return `<div style="display:flex; justify-content:space-between; align-items:center; gap:8px; border:1px solid var(--border); border-radius:8px; padding:8px 10px; margin-bottom:6px;">
        <span style="font-size:12px; color:var(--text-main); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(title || '—')}</span>
        <span style="font-size:10px; font-weight:800; color:${color}; background:color-mix(in srgb, ${color} 14%, transparent); padding:3px 9px; border-radius:999px; flex-shrink:0;">${label}</span>
      </div>`;
    }).join('') : `<div style="font-size:11.5px; color:var(--slate-soft);">${isAr ? 'ما ساهمت بأي حل بعد.' : "You haven't contributed anything yet."}</div>`;
  }

  async function submitContribution() {
    const isAr = currentLang === 'ar';
    const submittedBy = currentUserEmail;
    const cat = document.getElementById('contributeCat').value;
    const title = document.getElementById('contributeTitle').value.trim();
    const text = document.getElementById('contributeText').value.trim();
    if (!submittedBy) {
      showToast(isAr ? 'تعذّر التعرف على المستخدم، الرجاء تسجيل الدخول مجدداً.' : 'Could not identify the user, please sign in again.', 'error');
      return;
    }
    if (!title || !text) {
      showToast(isAr ? 'يرجى كتابة العنوان والنص.' : 'Please fill in a title and the text.', 'error');
      return;
    }
    const payload = { cat, submitted_by: submittedBy, status: 'pending' };
    if (isAr) { payload.title_ar = title; payload.text_ar = text; }
    else { payload.title = title; payload.text = text; }
    const { data, error } = await sb.from('script_submissions').insert(payload).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر إرسال المساهمة.' : 'Could not send the contribution.', 'error');
      return;
    }
    SCRIPT_SUBMISSIONS.unshift({
      id: data.id, cat: data.cat, title: data.title, titleAr: data.title_ar, text: data.text, textAr: data.text_ar,
      submittedBy: data.submitted_by, status: data.status, createdAt: new Date(data.created_at).getTime()
    });
    document.getElementById('contributeTitle').value = '';
    document.getElementById('contributeText').value = '';
    renderContributePanel();
    if (isAdmin) renderAdminLists();
    closePanelsByUser();
    showToast(isAr ? 'شكراً! تم إرسال مساهمتك للمراجعة.' : 'Thanks! Your contribution was sent for review.', 'success');
  }

  // Set right before switching to the Scripts tab pre-filled with a submission's content;
  // saveScript() checks this after a successful insert to mark the submission approved.
  let approvingSubmissionId = null;

  function approveSubmission(id) {
    const isAr = currentLang === 'ar';
    const sub = SCRIPT_SUBMISSIONS.find(s => s.id === id);
    if (!sub) return;
    approvingSubmissionId = id;
    switchAdminTab('scripts');
    document.getElementById('editScriptIndex').value = '-1';
    document.getElementById('newScriptCat').value = sub.cat;
    document.getElementById('newScriptTitle').value = sub.title || '';
    document.getElementById('newScriptTitleAr').value = sub.titleAr || '';
    document.getElementById('newScriptText').value = sub.text || '';
    document.getElementById('newScriptTextAr').value = sub.textAr || '';
    document.getElementById('saveScriptBtn').textContent = isAr ? '✅ نشر السكريبت' : '✅ Publish Script';
    showToast(isAr ? 'راجع النص أو ترجمه إذا لزم، ثم اضغط نشر.' : 'Review or translate the text, then click Publish.', 'success');
  }

  async function rejectSubmission(id) {
    const isAr = currentLang === 'ar';
    const { error } = await sb.from('script_submissions').update({ status: 'rejected', reviewed_by: currentUserEmail }).eq('id', id);
    if (error) {
      showToast(isAr ? 'تعذّر الرفض.' : 'Could not reject.', 'error');
      return;
    }
    const sub = SCRIPT_SUBMISSIONS.find(s => s.id === id);
    if (sub) sub.status = 'rejected';
    renderAdminLists();
    showToast(isAr ? 'تم رفض المساهمة.' : 'Contribution rejected.', 'success');
  }

  // ===================== Mentorship ("Buddy System") =====================
  let activeMentorTab = 'request';
  let openMentorThreadId = null;
  let mentorChatPollTimer = null;
  let DIRECTORY_EMAILS = [];

  // The mentor picker's option list — every email that can sign in (via the
  // list_directory_emails() RPC), so the trainee doesn't have to type one.
  async function loadDirectoryEmails() {
    const { data, error } = await sb.rpc('list_directory_emails');
    DIRECTORY_EMAILS = error ? [] : (data || []).map(r => r.email).filter(Boolean);
    renderMentorEmailOptions();
  }

  function renderMentorEmailOptions() {
    const sel = document.getElementById('mentorRequestEmail');
    if (!sel) return;
    const isAr = currentLang === 'ar';
    const previous = sel.value;
    // Exclude colleagues you already have a live request with (pending or accepted) —
    // no point offering to re-request someone who's already your mentor or who
    // already has your request sitting in their inbox. A declined request can be
    // retried, so it doesn't get excluded.
    const alreadyRequested = new Set(
      MENTOR_REQUESTS.filter(r => r.traineeEmail === currentUserEmail && r.status !== 'declined').map(r => r.mentorEmail)
    );
    const others = DIRECTORY_EMAILS.filter(e => e !== currentUserEmail && !alreadyRequested.has(e));
    const placeholder = `<option value="">${isAr ? '— اختر زميل —' : '— Select a colleague —'}</option>`;
    sel.innerHTML = placeholder + others.map(e => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`).join('');
    if (previous && others.includes(previous)) sel.value = previous;

    const grid = document.getElementById('mentorBrowseGrid');
    if (grid) {
      grid.innerHTML = others.length ? others.map(e => `
        <div class="mentor-browse-card">
          <span class="mp-avatar" style="background:${breakAvatarColor(e)}">${escapeHtml(breakInitials(e))}</span>
          <div class="mentor-browse-name">${escapeHtml(breakDisplayName(e))}</div>
          <button type="button" class="mentor-browse-ask-btn" data-ask-mentor="${escapeHtml(e)}">+ ${isAr ? 'اطلب رعاية' : 'Ask to mentor'}</button>
        </div>`).join('') : `<div class="mentorship-empty">${isAr ? 'كل الزملاء عندهم طلب منك أصلاً.' : "You've already asked everyone."}</div>`;
      const noteRow = document.getElementById('mentorRequestNoteRow');
      if (noteRow && (!sel.value || !others.includes(sel.value))) noteRow.style.display = 'none';
    }
  }

  function pickMentorToAsk(email) {
    const sel = document.getElementById('mentorRequestEmail');
    if (sel) sel.value = email;
    document.querySelectorAll('#mentorBrowseGrid .mentor-browse-card').forEach(card => {
      card.classList.toggle('picked', card.querySelector('[data-ask-mentor]')?.dataset.askMentor === email);
    });
    const noteRow = document.getElementById('mentorRequestNoteRow');
    const who = document.getElementById('mentorRequestNoteWho');
    const isAr = currentLang === 'ar';
    if (who) who.textContent = (isAr ? 'طلب رعاية لـ ' : 'Asking ') + breakDisplayName(email);
    if (noteRow) noteRow.style.display = 'flex';
    document.getElementById('mentorRequestNote')?.focus();
  }

  function mentorStatusLabel(status, isAr) {
    const map = {
      pending: isAr ? 'قيد الانتظار' : 'Pending',
      accepted: isAr ? 'مقبول' : 'Accepted',
      declined: isAr ? 'مرفوض' : 'Declined'
    };
    return map[status] || status;
  }

  function openMentorshipPage() {
    closePanels();
    closeScriptsPage();
    closeUpdatesPage();
    closeTechPage();
    closeTrainingPage();
    closeBreaksPage();
    switchMentorTab(activeMentorTab || 'request');
    document.getElementById('mentorshipPage').classList.add('open');
    pauseAllOrbits();
    pauseCmdHero();
    updateMentorNotifyBanner();
  }
  function closeMentorshipPage() {
    document.getElementById('mentorshipPage').classList.remove('open');
    stopMentorChatPoll();
    resumeCmdHero();
  }

  function switchMentorTab(tab) {
    activeMentorTab = tab;
    document.getElementById('mentorPaneRequest').style.display = tab === 'request' ? 'block' : 'none';
    document.getElementById('mentorPaneIncoming').style.display = tab === 'incoming' ? 'block' : 'none';
    document.getElementById('mentorPaneChats').style.display = tab === 'chats' ? 'block' : 'none';
    document.getElementById('mtabRequest').classList.toggle('active', tab === 'request');
    document.getElementById('mtabIncoming').classList.toggle('active', tab === 'incoming');
    document.getElementById('mtabChats').classList.toggle('active', tab === 'chats');
    if (tab !== 'chats') closeMentorThread();
    if (tab === 'request') renderMentorRequestPane();
    if (tab === 'incoming') renderMentorIncomingPane();
    if (tab === 'chats') renderMentorChatsList();
  }

  function renderMentorRequestPane() {
    const isAr = currentLang === 'ar';
    const list = document.getElementById('mentorOutgoingList');
    if (!list) return;
    const mine = MENTOR_REQUESTS.filter(r => r.traineeEmail === currentUserEmail).sort((a, b) => b.id - a.id);
    const table = document.getElementById('mentorOutgoingTable');
    const empty = document.getElementById('mentorOutgoingEmpty');
    const countEl = document.getElementById('mentorOutgoingCount');
    if (countEl) countEl.textContent = mine.length;
    if (!mine.length) {
      list.innerHTML = '';
      if (table) table.style.display = 'none';
      if (empty) empty.style.display = 'flex';
      return;
    }
    if (table) table.style.display = '';
    if (empty) empty.style.display = 'none';
    list.innerHTML = mine.map(r => `
      <tr>
        <td class="mentor-who-cell">${escapeHtml(breakDisplayName(r.mentorEmail))}</td>
        <td class="mentor-reason-cell">${r.note ? escapeHtml(r.note) : '—'}</td>
        <td><span class="mentor-status-pill ${r.status}">${mentorStatusLabel(r.status, isAr)}</span></td>
        <td class="mentor-date-cell">${new Date(r.createdAt).toLocaleDateString(isAr ? 'ar' : 'en', { day: 'numeric', month: 'long' })}</td>
      </tr>`).join('');
  }

  function renderMentorIncomingPane() {
    const isAr = currentLang === 'ar';
    const list = document.getElementById('mentorIncomingList');
    if (!list) return;
    const incoming = MENTOR_REQUESTS.filter(r => r.mentorEmail === currentUserEmail).sort((a, b) => b.id - a.id);
    list.innerHTML = incoming.length ? incoming.map(r => {
      const actions = r.status === 'pending'
        ? `<button class="mentor-accept-btn" data-accept-mentor="${r.id}">${isAr ? '✓ قبول' : '✓ Accept'}</button>
           <button class="mentor-decline-btn" data-decline-mentor="${r.id}">${isAr ? '✕ رفض' : '✕ Decline'}</button>`
        : `<span class="mentor-status-pill ${r.status}">${mentorStatusLabel(r.status, isAr)}</span>`;
      return `<div class="mentor-request-card">
        <div>
          <div class="who">${escapeHtml(breakDisplayName(r.traineeEmail))}</div>
          ${r.note ? `<div class="note">${escapeHtml(r.note)}</div>` : ''}
        </div>
        <div class="actions">${actions}</div>
      </div>`;
    }).join('') : `<div class="mentorship-empty">${isAr ? 'ما وصلك أي طلب رعاية بعد.' : 'No mentorship requests yet.'}</div>`;
  }

  async function sendMentorRequest() {
    const isAr = currentLang === 'ar';
    const traineeEmail = currentUserEmail;
    const mentorEmail = document.getElementById('mentorRequestEmail').value.trim();
    const note = document.getElementById('mentorRequestNote').value.trim();
    if (!traineeEmail) {
      showToast(isAr ? 'تعذّر التعرف على المستخدم، الرجاء تسجيل الدخول مجدداً.' : 'Could not identify the user, please sign in again.', 'error');
      return;
    }
    if (!mentorEmail) {
      showToast(isAr ? 'يرجى اختيار زميل من القائمة.' : 'Please pick a colleague from the list.', 'error');
      return;
    }
    if (mentorEmail.toLowerCase() === traineeEmail.toLowerCase()) {
      showToast(isAr ? 'ما بتقدر تطلب حالك راعي.' : "You can't request yourself as a mentor.", 'error');
      return;
    }
    const payload = { trainee_email: traineeEmail, mentor_email: mentorEmail, status: 'pending' };
    if (note) payload.note = note;
    const { data, error } = await sb.from('mentor_requests').insert(payload).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر إرسال الطلب.' : 'Could not send the request.', 'error');
      return;
    }
    MENTOR_REQUESTS.unshift({ id: data.id, traineeEmail: data.trainee_email, mentorEmail: data.mentor_email, note: data.note, status: data.status, createdAt: new Date(data.created_at).getTime() });
    document.getElementById('mentorRequestEmail').value = '';
    document.getElementById('mentorRequestNote').value = '';
    document.getElementById('mentorRequestNoteRow').style.display = 'none';
    renderMentorEmailOptions();
    renderMentorRequestPane();
    showToast(isAr ? 'تم إرسال طلب الرعاية!' : 'Mentorship request sent!', 'success');
  }

  async function respondMentorRequest(id, accept) {
    const isAr = currentLang === 'ar';
    const status = accept ? 'accepted' : 'declined';
    const { error } = await sb.from('mentor_requests').update({ status, responded_at: new Date().toISOString() }).eq('id', id);
    if (error) {
      showToast(isAr ? 'تعذّر تنفيذ الإجراء.' : 'Could not complete the action.', 'error');
      return;
    }
    const r = MENTOR_REQUESTS.find(x => x.id === id);
    if (r) r.status = status;
    renderMentorIncomingPane();
    updateMentorBadge();
    showToast(accept ? (isAr ? 'تم القبول! فتحت محادثة جديدة.' : 'Accepted! A new chat is open.') : (isAr ? 'تم الرفض.' : 'Declined.'), 'success');
  }

  // The most recently active mentorship gets the full growth-path treatment
  // (a real 3-stage progress track: sent -> accepted -> ongoing); the rest
  // just need to be reachable, so they're a simpler roster list underneath.
  function renderMentorChatsList() {
    const isAr = currentLang === 'ar';
    const list = document.getElementById('mentorChatsList');
    if (!list) return;
    const accepted = MENTOR_REQUESTS.filter(r => r.status === 'accepted' && (r.traineeEmail === currentUserEmail || r.mentorEmail === currentUserEmail)).sort((a, b) => b.id - a.id);
    if (!accepted.length) {
      list.innerHTML = `<div class="mentorship-empty">${isAr ? 'ما عندك محادثات نشطة بعد.' : "You don't have any active mentorships yet."}</div>`;
      return;
    }

    const describe = (r) => {
      const iAmMentor = r.mentorEmail === currentUserEmail;
      const other = iAmMentor ? r.traineeEmail : r.mentorEmail;
      const roleTag = iAmMentor ? (isAr ? 'إنت الراعي' : "You're the mentor") : (isAr ? 'إنت المتدرب' : "You're the trainee");
      return { other, roleTag };
    };

    const [hero, ...rest] = accepted;
    const { other: heroOther, roleTag: heroRole } = describe(hero);
    const stages = [
      { key: 'sent', label: isAr ? 'الطلب' : 'Request' },
      { key: 'accepted', label: isAr ? 'الموافقة' : 'Accepted' },
      { key: 'active', label: isAr ? 'متابعة نشطة' : 'Active' },
    ];
    const waypoints = stages.map((s, i) => {
      const isCurrent = i === stages.length - 1;
      return `<div class="mp-wp ${isCurrent ? 'current' : 'done'}"><span class="mp-node">${isCurrent ? '●' : '✓'}</span><span class="mp-label">${s.label}</span></div>`;
    }).join('');

    const heroHtml = `
      <div class="mentor-path-hero${hero.id === openMentorThreadId ? ' on' : ''}" data-open-thread="${hero.id}">
        <div class="mp-head">
          <span class="mp-avatar" style="background:${breakAvatarColor(heroOther)}">${escapeHtml(breakInitials(heroOther))}</span>
          <div><b>${escapeHtml(breakDisplayName(heroOther))}</b><span class="mp-role">${heroRole}</span></div>
          <span class="mp-since">${formatRelativeDay(hero.createdAt, isAr)}</span>
        </div>
        <div class="mp-track">
          <div class="mp-line"></div>
          <div class="mp-waypoints">${waypoints}</div>
        </div>
      </div>`;

    const restHtml = rest.map(r => {
      const { other, roleTag } = describe(r);
      return `<div class="mentor-chat-card${r.id === openMentorThreadId ? ' on' : ''}" data-open-thread="${r.id}">
        <span class="mp-avatar sm" style="background:${breakAvatarColor(other)}">${escapeHtml(breakInitials(other))}</span>
        <div>
          <div class="who">${escapeHtml(breakDisplayName(other))}</div>
          <div class="role-tag">${roleTag}</div>
        </div>
        <span>›</span>
      </div>`;
    }).join('');

    list.innerHTML = heroHtml + restHtml;
  }

  async function openMentorThread(requestId) {
    openMentorThreadId = requestId;
    const sheet = document.getElementById('mentorChatSheet');
    if (sheet) sheet.classList.add('open');
    document.querySelectorAll('#mentorChatsList [data-open-thread]').forEach(el => {
      el.classList.toggle('on', parseInt(el.dataset.openThread, 10) === requestId);
    });
    renderMentorThreadSideProfile(requestId);
    await loadAndRenderMentorMessages();
    startMentorChatPoll();
  }
  function closeMentorThread() {
    openMentorThreadId = null;
    stopMentorChatPoll();
    const sheet = document.getElementById('mentorChatSheet');
    if (sheet) sheet.classList.remove('open');
    document.querySelectorAll('#mentorChatsList [data-open-thread].on').forEach(el => el.classList.remove('on'));
  }

  // "Today" / "Yesterday" / full date, matching the Updates timeline's day-grouping labels.
  function formatRelativeDay(ts, isAr) {
    const d = new Date(ts);
    const now = new Date();
    const startOfDay = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diffDays = Math.round((startOfDay(now) - startOfDay(d)) / (24 * 60 * 60 * 1000));
    if (diffDays === 0) return isAr ? 'اليوم' : 'Today';
    if (diffDays === 1) return isAr ? 'أمس' : 'Yesterday';
    return d.toLocaleDateString(isAr ? 'ar' : 'en', { day: 'numeric', month: 'long' });
  }

  function renderMentorThreadSideProfile(requestId) {
    const isAr = currentLang === 'ar';
    const r = MENTOR_REQUESTS.find(x => x.id === requestId);
    if (!r) return;
    const iAmMentor = r.mentorEmail === currentUserEmail;
    const other = iAmMentor ? r.traineeEmail : r.mentorEmail;
    const roleTag = iAmMentor ? (isAr ? 'إنت الراعي' : "You're the mentor") : (isAr ? 'إنت المتدرب' : "You're the trainee");
    document.getElementById('mentorSideAvatar').textContent = breakInitials(other || '');
    document.getElementById('mentorSideAvatar').style.background = breakAvatarColor(other || '');
    document.getElementById('mentorSideName').textContent = other ? breakDisplayName(other) : '—';
    document.getElementById('mentorSideRole').textContent = roleTag;
  }

  function updateMentorThreadSideStats(requestId, messages) {
    const isAr = currentLang === 'ar';
    const r = MENTOR_REQUESTS.find(x => x.id === requestId);
    const countEl = document.getElementById('mentorSideCount');
    const lastEl = document.getElementById('mentorSideLast');
    if (countEl) countEl.textContent = messages.length;
    if (lastEl) {
      const lastTs = messages.length ? new Date(messages[messages.length - 1].created_at).getTime() : (r ? r.createdAt : null);
      lastEl.textContent = lastTs ? formatRelativeDay(lastTs, isAr) : '—';
    }
  }

  async function loadAndRenderMentorMessages() {
    if (!openMentorThreadId) return;
    const { data, error } = await sb.from('mentor_messages').select('*').eq('request_id', openMentorThreadId).order('id', { ascending: true });
    if (error) return;
    const wrap = document.getElementById('mentorChatMessages');
    if (!wrap) return;
    const wasNearBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
    const isAr = currentLang === 'ar';
    wrap.innerHTML = (data || []).map(m => {
      const mine = m.sender_email === currentUserEmail;
      const timeStr = new Date(m.created_at).toLocaleTimeString(isAr ? 'ar-EG' : 'en-US', { hour: '2-digit', minute: '2-digit' });
      const image = m.image_url ? `<img src="${escapeHtml(m.image_url)}" class="mentor-msg-image" alt="" loading="lazy">` : '';
      const textEl = m.text ? escapeHtml(m.text) : '';
      return `<div class="mentor-msg ${mine ? 'mine' : 'theirs'}${image ? ' has-image' : ''}">${image}${textEl}<span class="mentor-msg-time">${timeStr}</span></div>`;
    }).join('') || `<div class="mentorship-empty">${isAr ? 'ابدأ المحادثة...' : 'Start the conversation...'}</div>`;
    if (wasNearBottom) wrap.scrollTop = wrap.scrollHeight;
    updateMentorThreadSideStats(openMentorThreadId, data || []);
  }

  async function sendMentorMessage() {
    const input = document.getElementById('mentorChatInput');
    const text = input.value.trim();
    if (!text || !openMentorThreadId) return;
    input.value = '';
    const { error } = await sb.from('mentor_messages').insert({ request_id: openMentorThreadId, sender_email: currentUserEmail, text });
    if (error) {
      showToast(currentLang === 'ar' ? 'تعذّر إرسال الرسالة.' : 'Could not send the message.', 'error');
      return;
    }
    await loadAndRenderMentorMessages();
  }

  // Sends a pasted/attached screenshot as its own message (any text already
  // typed in the box is left alone - the image goes out immediately as a
  // separate bubble, same as pasting an image into any chat app).
  async function sendMentorImageMessage(file) {
    if (!openMentorThreadId) return;
    const isAr = currentLang === 'ar';
    const imageUrl = await uploadAttachmentImage(file, 'mentor-chat');
    if (!imageUrl) {
      showToast(isAr ? 'تعذّر رفع الصورة.' : 'Could not upload the image.', 'error');
      return;
    }
    const { error } = await sb.from('mentor_messages').insert({ request_id: openMentorThreadId, sender_email: currentUserEmail, text: '', image_url: imageUrl });
    if (error) {
      showToast(isAr ? 'تعذّر إرسال الصورة.' : 'Could not send the image.', 'error');
      return;
    }
    await loadAndRenderMentorMessages();
  }

  // A pasted screenshot (Ctrl/Cmd+V while the chat input is focused) sends
  // immediately as an image message instead of being dropped or pasted as
  // filename text - the common case this exists for is "take a screenshot,
  // paste it straight into the chat."
  function handleMentorChatPaste(e) {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
      if (item.type && item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) sendMentorImageMessage(file);
        return;
      }
    }
  }

  function startMentorChatPoll() {
    stopMentorChatPoll();
    mentorChatPollTimer = setInterval(loadAndRenderMentorMessages, 5000);
  }
  function stopMentorChatPoll() {
    clearInterval(mentorChatPollTimer);
    mentorChatPollTimer = null;
  }

  function updateMentorBadge() {
    const pendingCount = MENTOR_REQUESTS.filter(r => r.mentorEmail === currentUserEmail && r.status === 'pending').length;
    const label = pendingCount > 9 ? '9+' : String(pendingCount);
    [document.getElementById('nvhMentorBadge'), document.getElementById('mentorIncomingBadge')].forEach(badge => {
      if (!badge) return;
      if (pendingCount > 0) { badge.textContent = label; badge.style.display = 'flex'; }
      else badge.style.display = 'none';
    });
  }

  // ----- Live-ish mentor_requests updates, so a new incoming request, an
  // accepted/declined outcome, or a colleague becoming unavailable all show up
  // without a manual refresh. Polls on the same proven interval as the Updates
  // watcher (startUpdatesPolling) instead of Supabase Realtime — a WebSocket
  // subscription depends on the table being added to the supabase_realtime
  // publication and on Realtime being reachable at all, neither of which this
  // session can verify against the live project, whereas polling only needs a
  // plain REST call that's already known to work everywhere else in this app.
  // Runs from login regardless of whether the Mentorship page is ever opened,
  // same as the break-time watcher. -----
  function mapMentorRequestRow(r) {
    return {
      id: r.id, traineeEmail: r.trainee_email, mentorEmail: r.mentor_email, note: r.note,
      status: r.status, createdAt: new Date(r.created_at).getTime()
    };
  }
  const MENTOR_REQUESTS_POLL_MS = 15000;
  let mentorRequestsPollTimer = null;
  function startMentorRequestsPolling() {
    stopMentorRequestsPolling();
    mentorRequestsPollTimer = setInterval(pollMentorRequests, MENTOR_REQUESTS_POLL_MS);
  }
  function stopMentorRequestsPolling() {
    if (mentorRequestsPollTimer) { clearInterval(mentorRequestsPollTimer); mentorRequestsPollTimer = null; }
  }
  async function pollMentorRequests() {
    if (!currentUserEmail) return;
    const { data, error } = await sb.from('mentor_requests').select('*').order('id', { ascending: false });
    if (error) return;
    applyMentorRequestsSnapshot((data || []).map(mapMentorRequestRow));
  }
  // Diffs a freshly-fetched list against the current MENTOR_REQUESTS to fire the
  // right toast for what actually changed, then swaps in the new list and
  // re-renders whatever's currently on screen.
  function applyMentorRequestsSnapshot(freshList) {
    const isAr = currentLang === 'ar';
    const prevById = new Map(MENTOR_REQUESTS.map(r => [r.id, r]));
    freshList.forEach(row => {
      const prev = prevById.get(row.id);
      if (!prev) {
        if (row.mentorEmail === currentUserEmail) {
          showToast(isAr ? `📥 ${row.traineeEmail} أرسل لك طلب رعاية!` : `📥 ${row.traineeEmail} sent you a mentorship request!`, 'success');
        }
      } else if (prev.status === 'pending' && row.status !== 'pending' && row.traineeEmail === currentUserEmail) {
        const accepted = row.status === 'accepted';
        showToast(
          isAr
            ? (accepted ? `✅ ${row.mentorEmail} قبل طلب رعايتك!` : `${row.mentorEmail} رفض طلب رعايتك.`)
            : (accepted ? `✅ ${row.mentorEmail} accepted your mentorship request!` : `${row.mentorEmail} declined your mentorship request.`),
          accepted ? 'success' : 'error'
        );
      }
    });

    MENTOR_REQUESTS = freshList;
    updateMentorBadge();
    refreshHeroCounts();
    renderMentorEmailOptions();
    const mp = document.getElementById('mentorshipPage');
    if (mp && mp.classList.contains('open')) {
      if (activeMentorTab === 'request') renderMentorRequestPane();
      if (activeMentorTab === 'incoming') renderMentorIncomingPane();
      if (activeMentorTab === 'chats') renderMentorChatsList();
    }
  }

  function canDelete() {
    if (adminRole === 'full') return true;
    showToast(currentLang === 'ar' ? 'ما عندك صلاحية الحذف — راجع المشرف الكامل.' : "You don't have delete permission — contact the full admin.", 'error');
    return false;
  }

  function setCategory(cat) { activeCat = cat; render(); }

  // ===================== Technical Issue (شريط سفلي — مشاكل تقنية) =====================
  // البيانات مشتركة بين كل الموظفين عبر جدول technical_issues على Supabase.
  let TECH_ISSUES = [];
  let techIssuesLoadedOnce = false;
  let techAttachedNumber = null;

  const TECH_ISSUE_LABELS = {
    audio:  { ar: '🔇 الصوت بالمكالمة مشوش', en: '🔇 Audio is unclear' },
    closed: { ar: '📴 تم إغلاق المكالمة',     en: '📴 Call got disconnected' },
    delay:  { ar: '⏱️ تأخير في المكالمة',      en: '⏱️ Delay in the call' }
  };

  function goHome() {
    closePanels();
    closeScriptsPage();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTechPage();
    closeTrainingPage();
    closeBreaksPage();
    closeAdminModal();
    setCategory(null);
    const searchEl = document.getElementById('searchInput');
    if (searchEl) searchEl.value = '';
    render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    orbitControllers.orbitCanvasHome.start();
    maybeResumeOnboarding();
  }

  function openTechPage() {
    closePanels();
    closeScriptsPage();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTrainingPage();
    closeBreaksPage();
    resetTechForm();
    document.getElementById('techPage').classList.add('open');
    const searchEl = document.getElementById('techRecordSearch');
    if (searchEl) searchEl.value = '';
    // First open in the session: nothing cached yet, so show the loading skeleton while
    // the full table fetches. Every open after that renders instantly from the already-
    // loaded TECH_ISSUES and refreshes it quietly in the background — no more re-showing
    // the skeleton and waiting on a network round trip every single time this page opens.
    if (techIssuesLoadedOnce) {
      renderTechSheet();
      loadTechIssues();
    } else {
      showTechSkeleton();
      loadTechIssues();
    }
    pauseAllOrbits();
    pauseCmdHero();
    orbitControllers.orbitCanvasTech.start();
  }

  function closeTechPage() {
    document.getElementById('techPage').classList.remove('open');
    orbitControllers.orbitCanvasTech.stop();
    orbitControllers.orbitCanvasHome.start();
    resumeCmdHero();
  }

  function resetTechForm() {
    techAttachedNumber = null;
    const numInput = document.getElementById('techNumberInput');
    numInput.value = '';
    numInput.disabled = false;
    document.getElementById('techAttachBtn').disabled = false;
    document.querySelector('.tech-number-row').style.display = 'flex';
    document.getElementById('techAttachedRow').style.display = 'none';
    document.getElementById('techOptionsWrap').style.display = 'none';
    setTechOptionsDisabled(false);
  }

  function setTechOptionsDisabled(disabled) {
    ['techOptAudio', 'techOptClosed', 'techOptDelay'].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = disabled;
    });
  }

  function attachTechNumber() {
    const isAr = currentLang === 'ar';
    const val = document.getElementById('techNumberInput').value.trim();
    if (!val) {
      showToast(isAr ? 'يرجى إدخال الرقم أولاً.' : 'Please enter the number first.', 'error');
      return;
    }
    techAttachedNumber = val;
    document.querySelector('.tech-number-row').style.display = 'none';
    document.getElementById('techAttachedNum').textContent = val;
    document.getElementById('techAttachedRow').style.display = 'flex';
    document.getElementById('techOptionsWrap').style.display = 'block';
  }

  function changeTechNumber() {
    resetTechForm();
    document.getElementById('techNumberInput').focus();
  }

  async function submitTechIssue(issueKey) {
    const isAr = currentLang === 'ar';
    if (!techAttachedNumber) {
      showToast(isAr ? 'يرجى إرفاق الرقم أولاً.' : 'Please attach the number first.', 'error');
      return;
    }
    if (!currentUserEmail) {
      showToast(isAr ? 'تعذّر التعرف على المستخدم، الرجاء تسجيل الدخول مجدداً.' : 'Could not identify the user, please sign in again.', 'error');
      return;
    }
    setTechOptionsDisabled(true);
    const { error } = await sb.from('technical_issues').insert({
      phone_number: techAttachedNumber,
      issue_type: issueKey,
      employee_email: currentUserEmail
    });
    if (error) {
      setTechOptionsDisabled(false);
      showToast(isAr ? 'تعذّر تسجيل المشكلة.' : 'Could not log the issue.', 'error');
      return;
    }
    showToast(isAr ? 'تم تسجيل المشكلة بنجاح.' : 'The issue was logged successfully.', 'success');
    markOnboardingStepDone('issue');
    resetTechForm();
    await loadTechIssues();
  }

  async function loadTechIssues() {
    const { data, error } = await sb.from('technical_issues').select('*').order('id', { ascending: false });
    if (!error) {
      TECH_ISSUES = (data || []).map(r => ({
        id: r.id,
        phoneNumber: r.phone_number,
        issueType: r.issue_type,
        employeeEmail: r.employee_email,
        createdAt: r.created_at
      }));
      techIssuesLoadedOnce = true;
    }
    renderTechSheet();
  }

  function showTechSkeleton() {
    const body = document.getElementById('techSheetBody');
    const empty = document.getElementById('techSheetEmpty');
    if (!body) return;
    empty.style.display = 'none';
    let rows = '';
    for (let i = 0; i < 5; i++) {
      rows += `<tr class="tech-skeleton-row">
        <td><div class="tech-skeleton-bar" style="width:60%"></div></td>
        <td><div class="tech-skeleton-bar" style="width:75%"></div></td>
        <td><div class="tech-skeleton-bar" style="width:85%"></div></td>
        <td><div class="tech-skeleton-bar" style="width:55%"></div></td>
        <td></td>
      </tr>`;
    }
    body.innerHTML = rows;
  }

  function getFilteredTechIssues() {
    const searchEl = document.getElementById('techRecordSearch');
    const q = searchEl ? searchEl.value.trim().toLowerCase() : '';
    if (!q) return TECH_ISSUES;
    const isAr = currentLang === 'ar';
    return TECH_ISSUES.filter(t => {
      const lbl = TECH_ISSUE_LABELS[t.issueType];
      const issueText = lbl ? (isAr ? lbl.ar : lbl.en) + ' ' + (lbl.ar || '') + ' ' + (lbl.en || '') : (t.issueType || '');
      const pool = `${t.phoneNumber || ''} ${t.employeeEmail || ''} ${issueText}`.toLowerCase();
      return pool.includes(q);
    });
  }

  // Plain CSV — opens directly in both Excel and Google Sheets, no extra library needed.
  function exportTechIssuesCSV() {
    const isAr = currentLang === 'ar';
    const filtered = getFilteredTechIssues();
    if (!filtered.length) {
      showToast(isAr ? 'لا توجد بيانات لتصديرها.' : 'No data to export.', 'error');
      return;
    }
    const csvCell = (val) => {
      let s = String(val == null ? '' : val);
      // Formula/CSV injection guard: a phoneNumber value is an employee-controlled free-text
      // field. If it starts with =, +, -, or @, Excel/Sheets treats the cell as a formula on
      // open — a malicious value like `=HYPERLINK(...)` would run as a live formula on
      // whoever opens this export. Prefixing with a tab neutralizes that without changing
      // how the value displays.
      if (/^[=+\-@]/.test(s)) s = '\t' + s;
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const headers = isAr ? ['الرقم', 'المشكلة', 'الموظف', 'الوقت'] : ['Number', 'Issue', 'Employee', 'Time'];
    const rows = filtered.map(t => {
      const lbl = TECH_ISSUE_LABELS[t.issueType];
      const issueText = lbl ? (isAr ? lbl.ar : lbl.en) : (t.issueType || '');
      const dateStr = t.createdAt ? new Date(t.createdAt).toLocaleString(isAr ? 'ar-EG' : 'en-US') : '';
      return [t.phoneNumber || '', issueText, t.employeeEmail || '', dateStr].map(csvCell).join(',');
    });
    // Leading BOM so Excel renders Arabic text correctly instead of mojibake.
    const csv = '\uFEFF' + [headers.map(csvCell).join(','), ...rows].join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `technical-issues-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // Mission-control stat tiles above the live board: total logged, logged today, most common issue type.
  function renderTechStats() {
    const isAr = currentLang === 'ar';
    const totalEl = document.getElementById('techStatTotal');
    const todayEl = document.getElementById('techStatToday');
    const topEl = document.getElementById('techStatTop');
    if (!totalEl) return;

    totalEl.textContent = TECH_ISSUES.length;

    const todayStr = new Date().toDateString();
    const todayCount = TECH_ISSUES.filter(t => t.createdAt && new Date(t.createdAt).toDateString() === todayStr).length;
    todayEl.textContent = todayCount;

    if (!TECH_ISSUES.length) {
      topEl.textContent = '—';
    } else {
      const counts = {};
      TECH_ISSUES.forEach(t => { counts[t.issueType] = (counts[t.issueType] || 0) + 1; });
      const topType = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
      const lbl = TECH_ISSUE_LABELS[topType];
      topEl.textContent = lbl ? (isAr ? lbl.ar : lbl.en) : (topType || '—');
    }
  }

  function renderTechSheet() {
    const isAr = currentLang === 'ar';
    const body = document.getElementById('techSheetBody');
    const empty = document.getElementById('techSheetEmpty');
    const countEl = document.getElementById('techSheetCount');
    const filtered = getFilteredTechIssues();

    renderTechStats();
    if (countEl) countEl.textContent = filtered.length;

    const headCount = document.getElementById('techHeadCount');
    if (headCount) headCount.textContent = TECH_ISSUES.length ? (isAr ? `${TECH_ISSUES.length} مشكلة مسجلة` : `${TECH_ISSUES.length} issues logged`) : '';

    if (!filtered.length) {
      body.innerHTML = '';
      empty.style.display = 'block';
      const emptyTitle = document.getElementById('techEmptyTitle');
      const emptySub = document.getElementById('techEmptySub');
      if (emptyTitle && emptySub) {
        if (TECH_ISSUES.length && !filtered.length) {
          emptyTitle.textContent = isAr ? 'لا توجد نتائج مطابقة' : 'No matching results';
          emptySub.textContent = isAr ? 'جرّب كلمة بحث أخرى.' : 'Try a different search term.';
        } else {
          emptyTitle.textContent = isAr ? 'لا توجد مشاكل مسجلة بعد' : 'No issues logged yet';
          emptySub.textContent = isAr ? 'ستظهر المشاكل هنا فور تسجيلها' : 'Logged issues will appear here';
        }
      }
      return;
    }
    empty.style.display = 'none';
    const pillClass = { audio: 'pill-audio', closed: 'pill-closed', delay: 'pill-delay' };
    const numIcon = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 4h4l2 5-2.5 1.5a11 11 0 0 0 5.5 5.5L15 13l5 2v4a2 2 0 0 1-2 2C9.5 21 3 14.5 3 6.5a2 2 0 0 1 1.5-2Z"></path></svg>`;
    body.innerHTML = filtered.map(t => {
      const lbl = TECH_ISSUE_LABELS[t.issueType];
      const issueText = lbl ? (isAr ? lbl.ar : lbl.en) : escapeHtml(t.issueType || '');
      const dateStr = t.createdAt ? new Date(t.createdAt).toLocaleString(isAr ? 'ar-EG' : 'en-US', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';
      return `<tr>
        <td><div class="tech-num-cell"><span class="num-icon">${numIcon}</span>${escapeHtml(t.phoneNumber || '')}</div></td>
        <td><span class="tech-issue-pill ${pillClass[t.issueType] || 'pill-audio'}">${issueText}</span></td>
        <td class="tech-emp-cell">${escapeHtml(t.employeeEmail || '—')}</td>
        <td class="tech-time-cell">${dateStr}</td>
        <td><button class="tech-row-del" data-del-tech="${t.id}" title="${isAr ? 'حذف' : 'Delete'}">🗑️</button></td>
      </tr>`;
    }).join('');
  }

  async function deleteTechIssue(id) {
    if (!canDelete()) return;
    const { error } = await sb.from('technical_issues').delete().eq('id', id);
    if (error) {
      showToast(currentLang === 'ar' ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    TECH_ISSUES = TECH_ISSUES.filter(t => t.id !== id);
    renderTechSheet();
  }

  function createCard(title, text, color, badge, index, usageCount = 0, followObj = null) {
    const isAr = currentLang === 'ar';
    const card = document.createElement('div');
    card.className = 'card';
    card.style.setProperty('--card-accent', color);
    card.style.setProperty('--enter-delay', `${Math.min(renderSequence++, 10) * 42}ms`);

    const copyTxt = isAr ? 'نسخ النص' : 'Copy Text';
    const editTxt = isAr ? 'تعديل' : 'Edit';
    const delTxt = isAr ? 'حذف' : 'Delete';
    const usageTxt = isAr ? `تم النسخ ${usageCount} مرة` : `Used ${usageCount} times`;
    const trackPlaceholder = isAr ? 'أدخل رقم تتبع الشحنة' : 'Enter shipment tracking number';

    const iconCopy = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="12" height="12" rx="2.5"></rect><path d="M5.5 15.5H4.8A1.8 1.8 0 0 1 3 13.7V4.8A1.8 1.8 0 0 1 4.8 3h8.9A1.8 1.8 0 0 1 15.5 4.8v.7"></path></svg>`;
    const iconEdit = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20l1-4.2L16.6 4.2a1.8 1.8 0 0 1 2.6 0l.6.6a1.8 1.8 0 0 1 0 2.6L8.2 19 4 20Z"></path><path d="M14.5 6.3l3.2 3.2"></path></svg>`;
    const iconDelete = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 7h14"></path><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"></path><path d="M7 7l1 12.5A2 2 0 0 0 10 21h4a2 2 0 0 0 2-1.5L17 7"></path><path d="M10 11v6M14 11v6"></path></svg>`;
    const iconUsage = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="16" rx="2"></rect><path d="M9 3.5h6a1 1 0 0 1 1 1V6H8V4.5a1 1 0 0 1 1-1Z" fill="currentColor" stroke="none"></path><path d="M9 13l2 2 4-4"></path></svg>`;
    card.innerHTML = `
      <div class="card-top">
        <span class="badge">${escapeHtml(badge)}</span>
        <span class="usage-badge">${iconUsage}${usageTxt}</span>
      </div>
      <div class="card-title">${escapeHtml(title)}</div>
      <div class="card-text">${escapeHtml(text)}</div>
      <div class="track-row">
        <input type="text" class="track-input" maxlength="60" placeholder="${escapeHtml(trackPlaceholder)}" aria-label="${escapeHtml(trackPlaceholder)}">
      </div>
      <div class="card-actions">
        <button class="copy-btn" type="button" title="${escapeHtml(copyTxt)}" aria-label="${escapeHtml(copyTxt)}">${iconCopy}</button>
        ${index >= 0 ? `
          <button class="edit-btn" data-edit-idx="${index}" title="${escapeHtml(editTxt)}" aria-label="${escapeHtml(editTxt)}">${iconEdit}</button>
          <button class="delete-btn" data-del-idx="${index}" title="${escapeHtml(delTxt)}" aria-label="${escapeHtml(delTxt)}">${iconDelete}</button>
        ` : ''}
      </div>
    `;
    if (index >= 0) {
      card.querySelector('.edit-btn').addEventListener('click', function () { editScript(index); });
      card.querySelector('.delete-btn').addEventListener('click', function () { deleteScript(index); });
    }
    card.querySelector('.copy-btn').addEventListener('click', function () {
      handleCopy(text, this, index);
    });
    const trackInputEl = card.querySelector('.track-input');
    if (trackInputEl) {
      trackInputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); card.querySelector('.copy-btn').click(); }
      });
    }
    return card;
  }

  function handleCopy(txt, btn, index) {
    const card = btn.closest('.card');
    const trackInput = card ? card.querySelector('.track-input') : null;
    const trackVal = trackInput ? trackInput.value.trim() : '';
    const isAr = currentLang === 'ar';
    const trackLabel = isAr ? 'رقم التتبع الخاص بالشحنة' : 'Shipment Tracking Number';
    const finalText = trackVal ? `${trackLabel}: ${trackVal}\n\n${txt}` : txt;
    navigator.clipboard.writeText(finalText);
    const iconUsage = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="16" rx="2"></rect><path d="M9 3.5h6a1 1 0 0 1 1 1V6H8V4.5a1 1 0 0 1 1-1Z" fill="currentColor" stroke="none"></path><path d="M9 13l2 2 4-4"></path></svg>`;
    const iconCopy = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="12" height="12" rx="2.5"></rect><path d="M5.5 15.5H4.8A1.8 1.8 0 0 1 3 13.7V4.8A1.8 1.8 0 0 1 4.8 3h8.9A1.8 1.8 0 0 1 15.5 4.8v.7"></path></svg>`;
    const iconCheck = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 12.5l5 5 10-11"></path></svg>`;

    // Count analytics silently
    if(index >= 0 && SCRIPTS[index]) {
      SCRIPTS[index].usageCount = (SCRIPTS[index].usageCount || 0) + 1;
      const usageBadge = btn.closest('.card').querySelector('.usage-badge');
      const count = SCRIPTS[index].usageCount;
      const usageTxt = currentLang === 'ar' ? `تم النسخ ${count} مرة` : `Used ${count} times`;
      usageBadge.innerHTML = iconUsage + usageTxt;
      sb.rpc('increment_script_usage', { script_id: SCRIPTS[index].id })
        .then(({ error }) => { if (error) console.error('تعذّر تحديث عداد الاستخدام:', error.message); });
    }

    const copyTitle = isAr ? 'نسخ النص' : 'Copy Text';
    const copiedTitle = isAr ? 'تم النسخ!' : 'Copied!';
    btn.innerHTML = iconCheck;
    btn.title = copiedTitle;
    btn.setAttribute('aria-label', copiedTitle);
    btn.classList.add('copied');
    setTimeout(() => {
      btn.innerHTML = iconCopy;
      btn.title = copyTitle;
      btn.setAttribute('aria-label', copyTitle);
      btn.classList.remove('copied');
      if (trackInput) trackInput.value = '';
    }, 1200);

  }

  async function deleteScript(index) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const script = SCRIPTS[index];
    if(confirm(isAr ? 'هل أنت تأكد من الحذف؟' : 'Are you sure you want to delete this script?')) {
      const { error } = await sb.from('scripts').delete().eq('id', script.id);
      if (error) {
        showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
        return;
      }
      SCRIPTS.splice(index, 1);
      render();
    }
  }

  function editScript(index) {
    const script = SCRIPTS[index];
    openAdminModal();
    switchAdminTab('scripts');
    document.getElementById('editScriptIndex').value = index;
    document.getElementById('newScriptCat').value = script.cat;
    document.getElementById('newScriptTitle').value = script.title || '';
    document.getElementById('newScriptTitleAr').value = script.titleAr || '';
    document.getElementById('newScriptText').value = script.text || '';
    document.getElementById('newScriptTextAr').value = script.textAr || '';
    document.getElementById('saveScriptBtn').textContent = '💾 حفظ التعديلات / Save Changes';
  }

  // فتح لوحة الإدارة بيصير مسموح بس إذا البوزيشن تبع المستخدم (من جدول profiles) بتسمح.
  function openAdminModal() {
    const isAr = currentLang === 'ar';
    if (!isAdmin) {
      showToast(isAr ? 'ما عندك صلاحية الوصول لهذه اللوحة.' : "You don't have access to this panel.", 'error');
      return;
    }
    document.getElementById('adminAuthSection').style.display = 'none';
    document.getElementById('adminEditSection').style.display = 'block';
    document.getElementById('adminModal').classList.add('active');
    renderAdminLists();
  }
  function closeAdminModal() {
    document.getElementById('adminModal').classList.remove('active');
    stopPresenceAdminRefresh();
  }

  // ----- Image lightbox: click any attached photo (update card, chat bubble)
  // to view it full-size instead of squeezed into its small inline thumbnail. -----
  function openImageLightbox(src) {
    document.getElementById('imageLightboxImg').src = src;
    document.getElementById('imageLightbox').classList.add('active');
  }
  function closeImageLightbox() {
    document.getElementById('imageLightbox').classList.remove('active');
    document.getElementById('imageLightboxImg').src = '';
  }

  function updateAdminRoleLabel() {
    const isAr = currentLang === 'ar';
    const el = document.getElementById('lblAdminActive');
    const lockTabBtn = document.getElementById('btnTab9');
    if (lockTabBtn) lockTabBtn.style.display = adminRole === 'full' ? 'inline-flex' : 'none';
    const auditTabBtn = document.getElementById('btnTab10');
    if (auditTabBtn) auditTabBtn.style.display = adminRole === 'full' ? 'inline-flex' : 'none';
    if (!el) return;
    const perm = ROLE_PERMISSIONS[currentUserRole];
    const roleName = perm ? (isAr ? perm.label.ar : perm.label.en) : '';
    if (adminRole === 'limited') {
      el.textContent = isAr ? `✅ وضع مشرف محدود مفعّل (${roleName} — إضافة فقط، بدون حذف)` : `✅ Limited Admin Mode Active (${roleName} — Add only, no delete)`;
    } else if (adminRole === 'full') {
      el.textContent = isAr ? `✅ وضع الأدمن مفعّل (${roleName})` : `✅ Admin Mode Active (${roleName})`;
    }
  }

  function switchAdminTab(type) {
    if (type !== 'scripts') approvingSubmissionId = null;
    document.getElementById('adminTabScripts').style.display = type === 'scripts' ? 'block' : 'none';
    document.getElementById('adminTabCategories').style.display = type === 'categories' ? 'block' : 'none';
    document.getElementById('adminTabPanels').style.display = type === 'panels' ? 'block' : 'none';
    document.getElementById('adminTabUpdates').style.display = type === 'updates' ? 'block' : 'none';
    document.getElementById('adminTabSuggestions').style.display = type === 'suggestions' ? 'block' : 'none';
    document.getElementById('adminTabPresence').style.display = type === 'presence' ? 'block' : 'none';
    document.getElementById('adminTabTraining').style.display = type === 'training' ? 'block' : 'none';
    document.getElementById('adminTabContributions').style.display = type === 'contributions' ? 'block' : 'none';
    document.getElementById('adminTabLock').style.display = type === 'lock' ? 'block' : 'none';
    document.getElementById('adminTabAudit').style.display = type === 'audit' ? 'block' : 'none';

    document.getElementById('btnTab1').classList.toggle('active', type === 'scripts');
    document.getElementById('btnTab2').classList.toggle('active', type === 'categories');
    document.getElementById('btnTab3').classList.toggle('active', type === 'panels');
    document.getElementById('btnTab4').classList.toggle('active', type === 'updates');
    document.getElementById('btnTab5').classList.toggle('active', type === 'suggestions');
    document.getElementById('btnTab6').classList.toggle('active', type === 'presence');
    document.getElementById('btnTab7').classList.toggle('active', type === 'training');
    document.getElementById('btnTab8').classList.toggle('active', type === 'contributions');
    document.getElementById('btnTab9').classList.toggle('active', type === 'lock');
    document.getElementById('btnTab10').classList.toggle('active', type === 'audit');

    if (type === 'lock') loadLockTabState();
    if (type === 'audit') loadAuditLog();

    if (type === 'presence') {
      loadPresenceUsers();
      startPresenceAdminRefresh();
    } else {
      stopPresenceAdminRefresh();
    }

    if (type === 'training') {
      switchTrainingSub('dashboard');
    }
  }

  function updateAdminDropdowns() {
    const sel = document.getElementById('newScriptCat');
    const isAr = currentLang === 'ar';
    if(sel) {
      sel.innerHTML = CATEGORIES.map(c => `<option value="${c.key}">${escapeHtml((isAr && c.labelAr) ? c.labelAr : c.label)}</option>`).join('');
    }
  }

  async function saveScript() {
    const isAr = currentLang === 'ar';
    const idx = parseInt(document.getElementById('editScriptIndex').value);
    const cat = document.getElementById('newScriptCat').value;
    const title = document.getElementById('newScriptTitle').value.trim();
    const titleAr = document.getElementById('newScriptTitleAr').value.trim();
    const text = document.getElementById('newScriptText').value.trim();
    const textAr = document.getElementById('newScriptTextAr').value.trim();

    if(!((title || titleAr) && (text || textAr))) return;

    const payload = {
      cat,
      title: title || titleAr,
      title_ar: titleAr || title,
      text: text || textAr,
      text_ar: textAr || text
    };

    if (idx >= 0) {
      const scriptId = SCRIPTS[idx].id;
      const { error } = await sb.from('scripts').update(payload).eq('id', scriptId);
      if (error) {
        showToast(isAr ? 'تعذّر حفظ التعديل.' : 'Could not save the changes.', 'error');
        return;
      }
      Object.assign(SCRIPTS[idx], { cat, title: payload.title, titleAr: payload.title_ar, text: payload.text, textAr: payload.text_ar });
      document.getElementById('editScriptIndex').value = "-1";
    } else {
      const { data, error } = await sb.from('scripts').insert({ ...payload, usage_count: 0 }).select().single();
      if (error) {
        showToast(isAr ? 'تعذّر إضافة السكريبت.' : 'Could not add the script.', 'error');
        return;
      }
      SCRIPTS.push({ id: data.id, cat: data.cat, title: data.title, titleAr: data.title_ar, text: data.text, textAr: data.text_ar, usageCount: 0 });
      if (approvingSubmissionId) {
        const subId = approvingSubmissionId;
        approvingSubmissionId = null;
        await sb.from('script_submissions').update({ status: 'approved', reviewed_by: currentUserEmail }).eq('id', subId);
        const sub = SCRIPT_SUBMISSIONS.find(s => s.id === subId);
        if (sub) sub.status = 'approved';
        renderAdminLists();
      }
    }
    document.getElementById('newScriptTitle').value = '';
    document.getElementById('newScriptTitleAr').value = '';
    document.getElementById('newScriptText').value = '';
    document.getElementById('newScriptTextAr').value = '';
    document.getElementById('saveScriptBtn').textContent = isAr ? '+ إضافة السكريبت' : '+ Add Script';
    render();
    showToast(isAr ? 'تم حفظ السكريبت بنجاح!' : 'Script saved successfully!', 'success');
  }

  async function addCategory() {
    const isAr = currentLang === 'ar';
    const label = document.getElementById('newCatLabel').value.trim();
    const labelAr = document.getElementById('newCatLabelAr').value.trim();
    const color = document.getElementById('newCatColor').value;
    if(!(label || labelAr)) return;
    const key = (label || labelAr).toLowerCase().replace(/[^a-z0-9]/g, '');
    const { error } = await sb.from('categories').insert({ key, label: label || labelAr, label_ar: labelAr || label, color });
    if (error) {
      showToast(isAr ? 'تعذّر إضافة التبويب (ربما الاسم مستخدم مسبقاً).' : 'Could not add the category (name may already exist).', 'error');
      return;
    }
    CATEGORIES.push({ key, label: label || labelAr, labelAr: labelAr || label, color });
    document.getElementById('newCatLabel').value = '';
    document.getElementById('newCatLabelAr').value = '';
    render();
    renderAdminLists();
  }

  async function deleteCategory(key) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    if(confirm('حذف التبويب سيؤدي لحذف السكريبتات التابعة له، هل أنت تأكد؟')) {
      const { error } = await sb.from('categories').delete().eq('key', key);
      if (error) {
        showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
        return;
      }
      CATEGORIES = CATEGORIES.filter(c => c.key !== key);
      SCRIPTS = SCRIPTS.filter(s => s.cat !== key);
      render();
      renderAdminLists();
    }
  }

  async function addGeneralInfo() {
    const isAr = currentLang === 'ar';
    const label = document.getElementById('newInfoLabel').value.trim();
    const val = document.getElementById('newInfoVal').value.trim();
    const labelAr = document.getElementById('newInfoLabelAr') ? document.getElementById('newInfoLabelAr').value.trim() : '';
    const valAr = document.getElementById('newInfoValAr') ? document.getElementById('newInfoValAr').value.trim() : '';
    if(!(label && val)) return;
    const { data, error } = await sb.from('general_info').insert({ label, val, label_ar: labelAr || null, val_ar: valAr || null }).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر الإضافة.' : 'Could not add.', 'error');
      return;
    }
    GENERAL_INFO.push({ id: data.id, label: data.label, labelAr: data.label_ar, val: data.val, valAr: data.val_ar });
    document.getElementById('newInfoLabel').value = '';
    document.getElementById('newInfoVal').value = '';
    if (document.getElementById('newInfoLabelAr')) document.getElementById('newInfoLabelAr').value = '';
    if (document.getElementById('newInfoValAr')) document.getElementById('newInfoValAr').value = '';
    render();
    renderAdminLists();
  }

  async function deleteGeneralInfo(idx) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const item = GENERAL_INFO[idx];
    const { error } = await sb.from('general_info').delete().eq('id', item.id);
    if (error) {
      showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    GENERAL_INFO.splice(idx, 1);
    render();
    renderAdminLists();
  }

  async function addEtiquette() {
    const isAr = currentLang === 'ar';
    const val = document.getElementById('newEtiquetteInput').value.trim();
    const valAr = document.getElementById('newEtiquetteInputAr') ? document.getElementById('newEtiquetteInputAr').value.trim() : '';
    if(!val) return;
    const { data, error } = await sb.from('etiquette_items').insert({ text: val, text_ar: valAr || null }).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر الإضافة.' : 'Could not add.', 'error');
      return;
    }
    ETIQUETTE_ITEMS.push({ id: data.id, text: data.text, textAr: data.text_ar });
    document.getElementById('newEtiquetteInput').value = '';
    if (document.getElementById('newEtiquetteInputAr')) document.getElementById('newEtiquetteInputAr').value = '';
    render();
    renderAdminLists();
  }

  async function deleteEtiquette(idx) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const item = ETIQUETTE_ITEMS[idx];
    const { error } = await sb.from('etiquette_items').delete().eq('id', item.id);
    if (error) {
      showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    ETIQUETTE_ITEMS.splice(idx, 1);
    render();
    renderAdminLists();
  }

  async function addCritical() {
    const isAr = currentLang === 'ar';
    const val = document.getElementById('newCriticalInput').value.trim();
    const valAr = document.getElementById('newCriticalInputAr') ? document.getElementById('newCriticalInputAr').value.trim() : '';
    if(!val) return;
    const { data, error } = await sb.from('critical_items').insert({ text: val, text_ar: valAr || null }).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر الإضافة.' : 'Could not add.', 'error');
      return;
    }
    CRITICAL_ITEMS.push({ id: data.id, text: data.text, textAr: data.text_ar });
    document.getElementById('newCriticalInput').value = '';
    if (document.getElementById('newCriticalInputAr')) document.getElementById('newCriticalInputAr').value = '';
    render();
    renderAdminLists();
  }

  async function deleteCritical(idx) {
    if (!canDelete()) return;
    const isAr = currentLang === 'ar';
    const item = CRITICAL_ITEMS[idx];
    const { error } = await sb.from('critical_items').delete().eq('id', item.id);
    if (error) {
      showToast(isAr ? 'تعذّر الحذف.' : 'Could not delete.', 'error');
      return;
    }
    CRITICAL_ITEMS.splice(idx, 1);
    render();
    renderAdminLists();
  }

  function renderAdminLists() {
    document.getElementById('generalAdminList').innerHTML = GENERAL_INFO.map((item, i) => 
      `<div style="display:flex; justify-content:space-between; align-items:center; font-size:11.5px; margin-bottom:3px;">
        <span><b>${escapeHtml(item.labelAr || item.label)} / ${escapeHtml(item.label)}:</b> ${escapeHtml(item.valAr || item.val)} / ${escapeHtml(item.val)}</span>
        <button class="danger-btn" data-del-general="${i}" style="background:none; border:none; color:#B91C1C; cursor:pointer;">🗑️</button>
      </div>`
    ).join('');

    document.getElementById('categoriesAdminList').innerHTML = CATEGORIES.map(c => 
      `<div style="display:flex; justify-content:space-between; align-items:center; font-size:12px; margin-bottom:4px;">
        <span><span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:${safeColor(c.color)}; margin-inline-end:5px;"></span>${escapeHtml(c.labelAr || c.label)} / ${escapeHtml(c.label)}</span>
        <button class="danger-btn" data-del-category="${escapeHtml(c.key)}" style="background:none; border:none; color:#B91C1C; cursor:pointer;">🗑️</button>
      </div>`
    ).join('');

    document.getElementById('etiquetteAdminList').innerHTML = ETIQUETTE_ITEMS.map((item, i) => 
      `<div style="display:flex; justify-content:space-between; align-items:center; font-size:11.5px; margin-bottom:3px;">
        <span>${escapeHtml(item.textAr || item.text)} / ${escapeHtml(item.text)}</span>
        <button class="danger-btn" data-del-etiquette="${i}" style="background:none; border:none; color:#B91C1C; cursor:pointer;">🗑️</button>
      </div>`
    ).join('');

    document.getElementById('criticalAdminList').innerHTML = CRITICAL_ITEMS.map((item, i) => 
      `<div style="display:flex; justify-content:space-between; align-items:center; font-size:11.5px; margin-bottom:3px;">
        <span>${escapeHtml(item.textAr || item.text)} / ${escapeHtml(item.text)}</span>
        <button class="danger-btn" data-del-critical="${i}" style="background:none; border:none; color:#B91C1C; cursor:pointer;">🗑️</button>
      </div>`
    ).join('');

    const sortedUpdates = [...UPDATES].sort((a, b) => b.id - a.id);
    document.getElementById('updatesAdminList').innerHTML = sortedUpdates.length ? sortedUpdates.map(u =>
      `<div style="display:flex; justify-content:space-between; align-items:center; gap:8px; font-size:11.5px; margin-bottom:5px;">
        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${u.imageUrl ? '📷 ' : ''}${escapeHtml(u.text || (u.imageUrl ? '(صورة بدون نص)' : ''))}</span>
        <button class="danger-btn" data-del-update="${u.id}" style="background:none; border:none; color:#B91C1C; cursor:pointer; flex-shrink:0;">🗑️</button>
      </div>`
    ).join('') : `<div style="font-size:11.5px; color:var(--slate-soft);">لا توجد تحديثات بعد.</div>`;

    const sortedSuggestions = [...SUGGESTIONS].sort((a, b) => b.id - a.id);
    document.getElementById('suggestionsAdminList').innerHTML = sortedSuggestions.length ? sortedSuggestions.map(s => {
      const dateStr = new Date(s.createdAt).toLocaleDateString('ar-EG', { day: 'numeric', month: 'short' });
      return `<div style="border-bottom:1px solid var(--border); padding:8px 0; margin-bottom:4px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
          <span style="font-weight:700; font-size:12px; color:#be185d;">${escapeHtml(s.name)}</span>
          <div style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
            <span style="font-size:10px; color:var(--slate-soft);">${dateStr}</span>
            <button class="danger-btn" data-del-suggestion="${s.id}" style="background:none; border:none; color:#B91C1C; cursor:pointer;">🗑️</button>
          </div>
        </div>
        <div style="font-size:12px; color:var(--text-main); margin-top:4px; white-space:pre-line;">${escapeHtml(s.text)}</div>
      </div>`;
    }).join('') : `<div style="font-size:11.5px; color:var(--slate-soft);">لا توجد اقتراحات بعد.</div>`;

    const isArAdmin = currentLang === 'ar';
    const catLabel = (key) => {
      const c = CATEGORIES.find(x => x.key === key);
      return c ? escapeHtml((isArAdmin && c.labelAr) ? c.labelAr : c.label) : escapeHtml(key || '—');
    };
    const contribStatusLabel = {
      pending: [isArAdmin ? 'قيد المراجعة' : 'Pending', '#D97706'],
      approved: [isArAdmin ? 'اتنشرت' : 'Published', '#10B981'],
      rejected: [isArAdmin ? 'مرفوض' : 'Rejected', '#B91C1C']
    };
    const sortedSubmissions = [...SCRIPT_SUBMISSIONS].sort((a, b) => b.id - a.id);
    document.getElementById('contributionsAdminList').innerHTML = sortedSubmissions.length ? sortedSubmissions.map(s => {
      const [label, color] = contribStatusLabel[s.status] || contribStatusLabel.pending;
      const title = (isArAdmin && s.titleAr) ? s.titleAr : (s.title || s.titleAr);
      const text = (isArAdmin && s.textAr) ? s.textAr : (s.text || s.textAr);
      const dateStr = new Date(s.createdAt).toLocaleDateString(isArAdmin ? 'ar-EG' : 'en-US', { day: 'numeric', month: 'short' });
      const actions = s.status === 'pending'
        ? `<button data-approve-sub="${s.id}" style="background:#10B981; color:#fff; border:none; padding:4px 11px; border-radius:999px; font-size:10.5px; font-weight:800; cursor:pointer;">${isArAdmin ? '✓ موافقة' : '✓ Approve'}</button>
           <button data-reject-sub="${s.id}" style="background:none; border:1px solid #B91C1C; color:#B91C1C; padding:4px 11px; border-radius:999px; font-size:10.5px; font-weight:800; cursor:pointer;">${isArAdmin ? '✕ رفض' : '✕ Reject'}</button>`
        : `<span style="font-size:10px; font-weight:800; color:${color}; background:color-mix(in srgb, ${color} 14%, transparent); padding:3px 9px; border-radius:999px;">${label}</span>`;
      return `<div style="border-bottom:1px solid var(--border); padding:8px 0; margin-bottom:4px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:8px; flex-wrap:wrap;">
          <div>
            <span style="font-weight:700; font-size:12px; color:#D97706;">${escapeHtml(title || '—')}</span>
            <span style="font-size:10px; color:var(--slate-soft); margin-inline-start:6px;">${catLabel(s.cat)} · ${escapeHtml(s.submittedBy || '')} · ${dateStr}</span>
          </div>
          <div style="display:flex; align-items:center; gap:6px; flex-shrink:0;">${actions}</div>
        </div>
        <div style="font-size:12px; color:var(--text-main); margin-top:4px; white-space:pre-line;">${escapeHtml(text || '')}</div>
      </div>`;
    }).join('') : `<div style="font-size:11.5px; color:var(--slate-soft);">${isArAdmin ? 'لا توجد مساهمات بعد.' : 'No contributions yet.'}</div>`;
  }

  // Opening a side panel used to leave the whole animated hero background (blurred
  // drifting blobs, flowing glow lines, the particle canvas) running at full cost
  // right underneath it - competing with the panel's own slide-in/backdrop-blur
  // transition for the same frame budget and making that transition visibly janky.
  // Pausing it for the moment the panel is open removes that competition; the hero
  // is dimmed behind the panel overlay anyway, so nothing is visually lost.
  function openPanel(type) {
    document.getElementById('overlay').classList.add('show');
    document.getElementById(type + 'Panel').classList.add('open');
    pauseCmdHero();
  }
  function closePanels() {
    const wasAnyOpen = document.querySelector('.side-panel.open') !== null;
    document.getElementById('overlay').classList.remove('show');
    document.querySelectorAll('.side-panel').forEach(p => p.classList.remove('open'));
    if (wasAnyOpen) resumeCmdHero();
  }
  function closePanelsByUser() {
    closePanels();
    if (document.getElementById('onboardingPage').classList.contains('open')) renderOnboardingPage();
  }

  // ===== ربط كل الأحداث برمجيًا (بدون onclick= داخل HTML) — مطلوب لتفعيل CSP بدون 'unsafe-inline' لـ script-src =====
  function bindStaticEvents() {
    const on = (id, evt, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(evt, fn); };

    // Command Center hero
    on('cmdScriptsBody', 'click', () => goToHeroSection('scripts'));
    const cmdRailEl = document.getElementById('cmdRail');
    if (cmdRailEl) {
      cmdRailEl.addEventListener('click', (e) => {
        const item = e.target.closest('.cmd-rail-item');
        if (!item) return;
        document.querySelectorAll('#cmdRail .cmd-rail-item').forEach(el => el.classList.toggle('on', el === item));
        setCategory(item.dataset.cat);
        openScriptsPage();
      });
    }
    on('cmdTechCard', 'click', () => goToHeroSection('tech'));
    on('cmdTrainingCard', 'click', () => goToHeroSection('training'));
    on('cmdMentorCard', 'click', () => goToHeroSection('mentorship'));
    on('cmdUpdatesCard', 'click', () => goToHeroSection('updates'));
    const cmdStarsEl = document.getElementById('cmdStars');
    if (cmdStarsEl) {
      for (let i = 0; i < 24; i++) {
        const s = document.createElement('span');
        s.style.left = Math.random() * 100 + '%';
        s.style.top = Math.random() * 100 + '%';
        s.style.animationDelay = (Math.random() * 3.4) + 's';
        cmdStarsEl.appendChild(s);
      }
    }

    document.querySelector('.qt-general').addEventListener('click', () => openPanel('general'));
    document.querySelector('.qt-critical').addEventListener('click', () => openPanel('critical'));
    document.querySelector('.qt-etiquette').addEventListener('click', () => openPanel('etiquette'));
    document.querySelector('.qt-suggest').addEventListener('click', () => openPanel('suggest'));
    document.querySelector('.qt-contribute').addEventListener('click', () => { renderContributePanel(); openPanel('contribute'); });

    on('swUpdateBtn', 'click', () => window.location.reload());
    on('mentorNotifyBtn', 'click', enablePushNotifications);

    on('onboardingSkipBtn', 'click', () => {
      const state = getOnboardingState();
      state.dismissed = true;
      setOnboardingState(state);
      closeOnboardingPage();
    });
    document.getElementById('onboardingSteps').addEventListener('click', (e) => {
      const btn = e.target.closest('.go');
      if (!btn || btn.disabled) return;
      const stepEl = btn.closest('[data-onboarding-step]');
      if (stepEl) onboardingStepAction(stepEl.dataset.onboardingStep);
    });

    on('overlay', 'click', closePanelsByUser);
    document.querySelectorAll('.panel-close').forEach(btn => btn.addEventListener('click', closePanelsByUser));
    on('updatesSearchInput', 'input', renderUpdatesPage);
    document.querySelectorAll('#updatesFilterChips .chip').forEach(chip => {
      chip.addEventListener('click', () => setUpdatesFilter(chip.dataset.updatesFilter));
    });

    on('btnSubmitSuggest', 'click', submitSuggestion);
    on('btnSubmitContribute', 'click', submitContribution);

    // صفحة الرعاية والتدريب (Mentorship)
    document.querySelectorAll('.mentorship-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchMentorTab(btn.dataset.mentorTab));
    });
    on('btnSendMentorRequest', 'click', sendMentorRequest);
    document.getElementById('mentorBrowseGrid').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-ask-mentor]');
      if (btn) pickMentorToAsk(btn.dataset.askMentor);
    });
    on('mentorChatSheetBackdrop', 'click', closeMentorThread);
    document.getElementById('mentorIncomingList').addEventListener('click', (e) => {
      const acceptBtn = e.target.closest('[data-accept-mentor]');
      if (acceptBtn) { respondMentorRequest(parseInt(acceptBtn.dataset.acceptMentor, 10), true); return; }
      const declineBtn = e.target.closest('[data-decline-mentor]');
      if (declineBtn) respondMentorRequest(parseInt(declineBtn.dataset.declineMentor, 10), false);
    });
    document.getElementById('mentorChatsList').addEventListener('click', (e) => {
      const card = e.target.closest('[data-open-thread]');
      if (card) openMentorThread(parseInt(card.dataset.openThread, 10));
    });
    on('mentorChatBackBtn', 'click', closeMentorThread);
    on('mentorChatSendBtn', 'click', sendMentorMessage);
    on('mentorChatInput', 'keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); sendMentorMessage(); } });
    on('mentorChatInput', 'paste', handleMentorChatPaste);

    document.querySelectorAll('.admin-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchAdminTab(btn.dataset.adminTab));
    });

    on('saveScriptBtn', 'click', saveScript);
    on('btnAddCat', 'click', addCategory);
    on('btnAddGen', 'click', addGeneralInfo);
    on('btnAddEtiq', 'click', addEtiquette);
    on('btnAddCrit', 'click', addCritical);
    on('btnAddUpd', 'click', addUpdate);
    on('newUpdAttachBtn', 'click', () => document.getElementById('newUpdImageInput').click());
    on('newUpdImageInput', 'change', (e) => pickNewUpdateImage(e.target.files[0]));
    on('newUpdImageRemoveBtn', 'click', clearNewUpdateImage);
    on('newUpdText', 'paste', handleNewUpdateTextPaste);
    on('btnCloseAdmin', 'click', closeAdminModal);
    on('imageLightboxClose', 'click', closeImageLightbox);
    document.getElementById('imageLightbox').addEventListener('click', (e) => {
      if (e.target.id === 'imageLightbox') closeImageLightbox();
    });
    document.body.addEventListener('click', (e) => {
      const img = e.target.closest('.update-image, .mentor-msg-image');
      if (img) openImageLightbox(img.src);
    });

    on('novaWordmark', 'dblclick', openAdminModal);
    on('profileBtn', 'click', toggleProfileMenu);
    on('skyThemeCheckbox', 'change', toggleTheme);
    on('profileLangBtn', 'click', toggleLanguage);
    on('logoutBtn', 'click', employeeLogout);
    on('btnSaveLock', 'click', saveLockState);
    on('btnRefreshAudit', 'click', loadAuditLog);
    on('searchInput', 'input', render);

    // تفويض الأحداث (event delegation) للعناصر يلي تتولّد ديناميكيًا بالجافاسكربت
    document.getElementById('tabs').addEventListener('click', (e) => {
      const tab = e.target.closest('.tab');
      if (!tab) return;
      const key = tab.dataset.cat;
      setCategory(key ? key : null);
    });

    document.getElementById('generalAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-general]');
      if (btn) deleteGeneralInfo(parseInt(btn.dataset.delGeneral, 10));
    });
    document.getElementById('categoriesAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-category]');
      if (btn) deleteCategory(btn.dataset.delCategory);
    });
    document.getElementById('etiquetteAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-etiquette]');
      if (btn) deleteEtiquette(parseInt(btn.dataset.delEtiquette, 10));
    });
    document.getElementById('criticalAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-critical]');
      if (btn) deleteCritical(parseInt(btn.dataset.delCritical, 10));
    });
    document.getElementById('updatesAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-update]');
      if (btn) deleteUpdate(parseInt(btn.dataset.delUpdate, 10));
    });
    document.getElementById('suggestionsAdminList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-suggestion]');
      if (btn) deleteSuggestion(parseInt(btn.dataset.delSuggestion, 10));
    });
    document.getElementById('contributionsAdminList').addEventListener('click', (e) => {
      const approveBtn = e.target.closest('[data-approve-sub]');
      if (approveBtn) { approveSubmission(parseInt(approveBtn.dataset.approveSub, 10)); return; }
      const rejectBtn = e.target.closest('[data-reject-sub]');
      if (rejectBtn) rejectSubmission(parseInt(rejectBtn.dataset.rejectSub, 10));
    });

    // الشريط السفلي الثابت
    on('bbHomeBtn', 'click', () => { launchHomePlanet(); goHome(); });

    // صفحة المشاكل التقنية
    on('techBackBtn', 'click', () => { closeTechPage(); maybeResumeOnboarding(); });
    on('techAttachBtn', 'click', attachTechNumber);
    on('techChangeNumBtn', 'click', changeTechNumber);
    on('techNumberInput', 'keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); attachTechNumber(); } });
    on('techRecordSearch', 'input', renderTechSheet);
    on('techExportBtn', 'click', exportTechIssuesCSV);
    document.querySelectorAll('.tech-opt-btn').forEach(btn => {
      btn.addEventListener('click', () => submitTechIssue(btn.dataset.issue));
    });
    document.getElementById('techSheetBody').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-tech]');
      if (btn) deleteTechIssue(parseInt(btn.dataset.delTech, 10));
    });

    // جدول البريكات
    on('breaksMenuBtn', 'click', () => { closeProfileMenu(); openBreaksPage(); });
    on('breaksAddSelectedBtn', 'click', addSelectedBreaksEmployees);
    document.getElementById('breaksAddChips').addEventListener('click', (e) => {
      const chip = e.target.closest('[data-add-email]');
      if (chip) toggleBreaksAddSelection(chip.dataset.addEmail);
    });
    on('breaksEditToggle', 'click', toggleBreaksEditMode);
    document.getElementById('breaksTableBody').addEventListener('click', (e) => {
      const editBtn = e.target.closest('.breaks-time-edit-btn');
      if (editBtn) { e.stopPropagation(); handleBreakTimeEditClick(editBtn); return; }
      const swapBtn = e.target.closest('.breaks-swap-request-btn');
      if (swapBtn) { e.stopPropagation(); openBreakSwapPicker(); return; }
      const removeBtn = e.target.closest('[data-remove-email]');
      if (removeBtn) { e.stopPropagation(); removeBreaksEmployee(removeBtn.dataset.removeEmail); return; }
      if (!breaksEditMode) return;
      const row = e.target.closest('.breaks-row');
      if (row) handleSeatSwapClick(parseInt(row.dataset.rowId, 10));
    });
    document.getElementById('breaksIncomingList').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-respond-swap]');
      if (btn) respondBreakSwap(parseInt(btn.dataset.respondSwap, 10), btn.dataset.accept === '1');
    });
    on('breakSwapCancel', 'click', closeBreakSwapPicker);
    on('breakSwapSend', 'click', sendBreakSwapRequest);
    document.getElementById('breakSwapOverlay').addEventListener('click', (e) => {
      if (e.target.id === 'breakSwapOverlay') closeBreakSwapPicker();
    });

    // مركز التدريب
    on('trainingSearchInput', 'input', renderTrainingGrid);
    on('trainingFooterBtn', 'click', () => openPanel('suggest'));
    on('trainingTreeBackBtn', 'click', backToTrainingGrid);
    document.getElementById('trainingGrid').addEventListener('click', (e) => {
      const cardEl = e.target.closest('[data-training-id]');
      if (cardEl) openTrainingTree(cardEl.dataset.trainingId);
    });
    bindTrainingAdminEvents();
  }
  bindStaticEvents();

  applyLanguage();
  setupKeyboardShortcuts();
  setupCardTilt();

  function launchHomePlanet() {
    const icon = document.getElementById('bbHomeIcon');
    const ring = document.getElementById('bbHomeLaunchRing');
    if (!icon || !ring) return;
    icon.classList.remove('bb-launch'); ring.classList.remove('go');
    void icon.offsetWidth; // restart animation if clicked repeatedly
    icon.classList.add('bb-launch'); ring.classList.add('go');
    setTimeout(() => { icon.classList.remove('bb-launch'); ring.classList.remove('go'); }, 650);
  }

  // Subtle cursor-reactive tilt + glow for .card elements (event-delegated so it
  // keeps working across re-renders without rebinding per card).
  function setupCardTilt() {
    let activeCard = null;
    document.addEventListener('mousemove', (e) => {
      const card = e.target.closest('.card');
      if (card !== activeCard) {
        if (activeCard) resetTilt(activeCard);
        activeCard = card;
      }
      if (!card) return;
      const r = card.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width;
      const py = (e.clientY - r.top) / r.height;
      card.style.setProperty('--rx', ((0.5 - py) * 4) + 'deg');
      card.style.setProperty('--ry', ((px - 0.5) * -4) + 'deg');
      card.style.setProperty('--mx', (px * 100) + '%');
      card.style.setProperty('--my', (py * 100) + '%');
    });
    document.addEventListener('mouseleave', () => { if (activeCard) { resetTilt(activeCard); activeCard = null; } }, true);
    function resetTilt(card) {
      card.style.removeProperty('--rx'); card.style.removeProperty('--ry');
      card.style.removeProperty('--mx'); card.style.removeProperty('--my');
    }
  }

  // ====== PWA: install the app-shell service worker (icons/scripts only — Supabase calls pass straight through) ======
  // Also watches for a freshly-deployed build and reloads automatically once
  // it's live, instead of leaving people on a stale version until they
  // happen to notice and refresh by hand. sw.js already calls
  // self.skipWaiting() unconditionally on install and self.clients.claim()
  // on activate, so a newly-installed worker takes over this page's
  // controller on its own within moments — "controllerchange" firing here
  // is exactly that moment, and is what actually triggers the reload. The
  // toast shown at "installed" is only a heads-up a beat earlier, so the
  // reload doesn't feel like an unexplained jump; #swUpdateBtn just skips
  // the (short) wait for anyone who clicks it first.
  if ('serviceWorker' in navigator) {
    let refreshingForUpdate = false;
    // clients.claim() in sw.js's activate handler ALSO fires controllerchange
    // on a page's very first-ever visit (going from no controller to
    // controlled) - not just on real updates. Ignore that first transition,
    // or every fresh session would reload itself once for no reason.
    let hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController) { hadController = true; return; }
      if (refreshingForUpdate) return;
      refreshingForUpdate = true;
      window.location.reload();
    });
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').then((reg) => {
        reg.addEventListener('updatefound', () => {
          const installing = reg.installing;
          if (!installing) return;
          installing.addEventListener('statechange', () => {
            // A worker reaching "installed" while an existing controller is active means
            // this is an update, not the very first install — that's when we prompt.
            if (installing.state === 'installed' && navigator.serviceWorker.controller) {
              const el = document.getElementById('swUpdateToast');
              if (el) el.classList.add('show');
            }
          });
        });
        setInterval(() => reg.update().catch(() => {}), 2 * 60 * 1000);
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') reg.update().catch(() => {});
        });
      }).catch(() => {});
    });
  }

  // Service-worker update detection above depends on browser-specific lifecycle
  // behavior (skipWaiting/clients.claim/controllerchange) that's known to be
  // inconsistent across browsers, particularly mobile Safari — it can end up
  // never firing at all on some devices. This is a second, much simpler
  // mechanism that doesn't touch the Service Worker API in any way: it just
  // asks the server "has app.js changed?" on a plain timer, using the same
  // ETag/Last-Modified caching header every static file server already sends.
  // Works identically everywhere, PWA or plain tab, any browser.
  (function watchForNewDeployByContent() {
    // Compares the actual response body (length + a slice from each end),
    // not a caching header - HEAD + ETag/Last-Modified turned out to not be
    // reliable enough to trust here, and this can't fail to detect a real
    // change since it never depends on any specific header being present.
    // Verified end-to-end on the live site: this is what actually reloads
    // an already-open tab onto a fresh deploy with zero manual action.
    //
    // Below, the SAME comparison (byte length + first 300 bytes + last 300
    // bytes) is still what decides "changed or not" — nothing about what's
    // being compared changed, only how those bytes get fetched: an HTTP
    // Range request for just those two small slices instead of downloading
    // the entire file, when the server honors it. If Range support can't be
    // confirmed (no 206, no usable Content-Range, or the request errors),
    // this permanently falls back to the original full-body fetch for the
    // rest of the tab's session — decided once, up front, so the signature
    // format can never flip mid-session and look like a false "changed".
    let knownSignature = null;
    let reloadingForNewDeploy = false;
    let rangeCheckMode = null; // decided once by probeRangeSupport(): true | false

    // A file's bytes, read as raw bytes (not decoded as UTF-8 text) and turned
    // into a comparable string one code unit per byte. This matters because
    // app.js/index.html contain Arabic text: a byte-Range slice can end in
    // the middle of a multi-byte UTF-8 character, and decoding that as text
    // (like the fallback's res.text() does on the *complete* file) would
    // produce a different, unstable result depending on exactly where a
    // change happens to fall. Comparing raw bytes sidesteps that entirely.
    function bytesToComparableString(bytes) {
      let out = '';
      for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
      return out;
    }
    async function fetchByteRange(path, rangeHeader) {
      const res = await fetch(path, { cache: 'no-store', headers: { Range: rangeHeader } });
      if (res.status !== 206) return null; // not honored as a partial response - can't trust it
      const contentRange = res.headers.get('content-range'); // e.g. "bytes 0-299/280532"
      const match = contentRange && /bytes \d+-\d+\/(\d+)/.exec(contentRange);
      if (!match) return null;
      const bytes = new Uint8Array(await res.arrayBuffer());
      if (!bytes.length) return null;
      return { totalBytes: parseInt(match[1], 10), bytes };
    }
    async function fileSignatureViaRange(path) {
      const [head, tail] = await Promise.all([
        fetchByteRange(path, 'bytes=0-299'),
        fetchByteRange(path, 'bytes=-300'),
      ]);
      if (!head || !tail || head.totalBytes !== tail.totalBytes) return null;
      return head.totalBytes + ':' + bytesToComparableString(head.bytes) + bytesToComparableString(tail.bytes);
    }
    async function fileSignatureViaFullBody(path) {
      const res = await fetch(path, { cache: 'no-store' });
      const text = await res.text();
      return text.length + ':' + text.slice(0, 300) + text.slice(-300);
    }
    // One-time capability check, run before the watcher ever starts comparing
    // anything - not decided lazily inside a real check, so a mixed result
    // (e.g. Range working for one file but not another on the same first
    // attempt) can't leave the watcher stuck. Whatever this decides is used
    // for the rest of the session; it is never re-evaluated afterward.
    async function probeRangeSupport() {
      try {
        rangeCheckMode = (await fileSignatureViaRange('/app.js')) !== null;
      } catch (err) {
        rangeCheckMode = false;
      }
    }
    async function fileSignature(path) {
      return rangeCheckMode ? fileSignatureViaRange(path) : fileSignatureViaFullBody(path);
    }
    async function checkForNewDeploy() {
      if (reloadingForNewDeploy) return;
      try {
        // Watches app.js AND style.css/index.html — a CSS-only or markup-only deploy
        // never touches app.js, so checking app.js alone misses those entirely.
        const [appSig, cssSig, htmlSig] = await Promise.all([
          fileSignature('/app.js'),
          fileSignature('/style.css'),
          fileSignature('/index.html'),
        ]);
        const signature = appSig + '|' + cssSig + '|' + htmlSig;
        if (knownSignature === null) { knownSignature = signature; return; }
        if (signature !== knownSignature) {
          reloadingForNewDeploy = true;
          window.location.reload();
        }
      } catch (err) { /* offline or blocked right now — just try again next tick */ }
    }
    probeRangeSupport().then(() => {
      checkForNewDeploy();
      setInterval(checkForNewDeploy, 20 * 1000);
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') checkForNewDeploy();
      });
    });
  })();

  // ====== Web Push: real OS notifications for mentor-chat messages, even with the site closed ======
  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; i++) outputArray[i] = rawData.charCodeAt(i);
    return outputArray;
  }
  function pushSupported() {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }
  async function saveSubscription(sub) {
    if (!currentUserEmail) return;
    const json = sub.toJSON();
    await sb.from('push_subscriptions').upsert({
      user_email: currentUserEmail,
      endpoint: json.endpoint,
      p256dh: json.keys.p256dh,
      auth: json.keys.auth,
    }, { onConflict: 'endpoint' });
  }
  function updateMentorNotifyBanner() {
    const el = document.getElementById('mentorNotifyBanner');
    if (!el) return;
    el.style.display = (pushSupported() && Notification.permission === 'default') ? 'flex' : 'none';
  }
  // User-gesture flow: the browser's own permission prompt only fires from a click.
  async function enablePushNotifications() {
    if (!pushSupported()) return;
    try {
      const permission = await Notification.requestPermission();
      updateMentorNotifyBanner();
      if (permission !== 'granted') return;
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY) });
      }
      await saveSubscription(sub);
      showToast(currentLang === 'ar' ? 'تم تفعيل الإشعارات!' : 'Notifications enabled!', 'success');
    } catch (e) { /* denied, unsupported, or dismissed — nothing to do */ }
  }
  // If permission was already granted on an earlier visit, keep this device's subscription
  // in sync silently — no re-prompt, matches the standing browser permission.
  async function syncPushSubscriptionIfGranted() {
    if (!pushSupported() || Notification.permission !== 'granted') return;
    try {
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY) });
      }
      await saveSubscription(sub);
    } catch (e) {}
  }

  // ===== New Hire Onboarding Journey =====
  function onboardingStore() {
    try { return JSON.parse(localStorage.getItem('fajer_onboarding_v1') || '{}'); } catch { return {}; }
  }
  function getOnboardingState() {
    const store = onboardingStore();
    return store[currentUserEmail] || { steps: {}, dismissed: false };
  }
  function setOnboardingState(state) {
    if (!currentUserEmail) return;
    const store = onboardingStore();
    store[currentUserEmail] = state;
    localStorage.setItem('fajer_onboarding_v1', JSON.stringify(store));
  }
  function isOnboardingStepDone(key, state) {
    // 'mentor' is derived live from MENTOR_REQUESTS (loaded unconditionally at boot).
    // The rest — including 'issue' — are localStorage flags set at the moment of the real
    // action, since TECH_ISSUES itself is only loaded lazily when the Tech page is opened.
    if (key === 'mentor') return MENTOR_REQUESTS.some(r => r.traineeEmail === currentUserEmail);
    return !!(state.steps && state.steps[key]);
  }
  function markOnboardingStepDone(key) {
    const state = getOnboardingState();
    state.steps = state.steps || {};
    state.steps[key] = true;
    setOnboardingState(state);
  }

  function renderOnboardingPage() {
    const isAr = currentLang === 'ar';
    const wrap = document.getElementById('onboardingSteps');
    if (!wrap) return;
    const state = getOnboardingState();
    let doneCount = 0;
    wrap.innerHTML = ONBOARDING_STEP_DEFS.map((s, i) => {
      const done = isOnboardingStepDone(s.key, state);
      if (done) doneCount++;
      return `<div class="onboarding-step${done ? ' done' : ''}" data-onboarding-step="${s.key}">
        <div class="chk">${done ? '✓' : i + 1}</div>
        <div class="info">
          <div class="title">${isAr ? s.title.ar : s.title.en}</div>
          <div class="sub">${isAr ? s.sub.ar : s.sub.en}</div>
        </div>
        <button class="go"${done ? ' disabled' : ''}>${done ? (isAr ? 'تمت' : 'Done') : (isAr ? 'ابدأ ←' : 'Start →')}</button>
      </div>`;
    }).join('');
    document.getElementById('onboardingRingPct').textContent = `${doneCount}/${ONBOARDING_STEP_DEFS.length}`;
    const circumference = 2 * Math.PI * 37;
    const ring = document.getElementById('onboardingRingProgress');
    if (ring) {
      ring.style.strokeDasharray = String(circumference);
      ring.style.strokeDashoffset = String(circumference * (1 - doneCount / ONBOARDING_STEP_DEFS.length));
    }
    return doneCount;
  }

  function openOnboardingPage() {
    closePanels();
    closeUpdatesPage();
    closeMentorshipPage();
    closeTechPage();
    closeTrainingPage();
    pauseAllOrbits();
    renderOnboardingPage();
    document.getElementById('onboardingPage').classList.add('open');
  }
  function closeOnboardingPage() {
    document.getElementById('onboardingPage').classList.remove('open');
  }

  // The training/mentor/issue steps navigate to a full page at onboarding's own z-index, so
  // it has to close first (see onboardingStepAction) — call this wherever the user can land
  // back on the plain dashboard with nothing else open, to resume the checklist right there
  // instead of leaving them on an empty dashboard until their next reload.
  function maybeResumeOnboarding() {
    if (!currentUserEmail) return;
    const anyPageOpen = ['techPage', 'trainingPage', 'mentorshipPage', 'updatesPage']
      .some(id => document.getElementById(id).classList.contains('open'));
    if (anyPageOpen) return;
    const state = getOnboardingState();
    if (state.dismissed) return;
    const allDone = ONBOARDING_STEP_DEFS.every(s => isOnboardingStepDone(s.key, state));
    if (allDone) { state.dismissed = true; setOnboardingState(state); return; }
    openOnboardingPage();
  }

  function onboardingStepAction(key) {
    // Info/etiquette open as a side panel, which sits ABOVE the onboarding page (z-index
    // 97/96 vs 95) — leave the onboarding page open underneath so it's there again, with
    // the step now checked off, the moment the panel closes. The other three steps navigate
    // to a full page at the same z-index as onboarding, so it has to be closed first or it
    // would just stay on top hiding the destination.
    if (key === 'info') { markOnboardingStepDone('info'); openPanel('general'); return; }
    if (key === 'etiquette') { markOnboardingStepDone('etiquette'); openPanel('etiquette'); return; }
    if (key === 'training') { closeOnboardingPage(); openTrainingPage(); return; }
    if (key === 'mentor') { closeOnboardingPage(); openMentorshipPage(); switchMentorTab('request'); return; }
    if (key === 'issue') { closeOnboardingPage(); openTechPage(); return; }
  }

  // Shown once per device to a user who has no prior activity at all (a real new hire);
  // an existing employee opening the app for the first time after this feature shipped is
  // inferred from having any real data already and silently skipped. The one-off tech-issues
  // existence check only ever runs on this first-ever classification for a (user, device)
  // pair — every later boot just reads the cached localStorage verdict.
  async function maybeShowOnboarding() {
    if (!currentUserEmail) return;
    const store = onboardingStore();
    if (!(currentUserEmail in store)) {
      let hasLoggedIssueBefore = false;
      try {
        const { data } = await sb.from('technical_issues').select('id').eq('employee_email', currentUserEmail).limit(1);
        hasLoggedIssueBefore = !!(data && data.length);
      } catch { /* best-effort — treat as no prior issue on failure */ }
      const hasMentorActivity = MENTOR_REQUESTS.some(r => r.traineeEmail === currentUserEmail || r.mentorEmail === currentUserEmail);
      const hasExistingActivity = isAdmin || hasMentorActivity || hasLoggedIssueBefore;
      store[currentUserEmail] = { steps: { issue: hasLoggedIssueBefore }, dismissed: hasExistingActivity };
      localStorage.setItem('fajer_onboarding_v1', JSON.stringify(store));
    }
    const state = store[currentUserEmail];
    if (state.dismissed) return;
    const allDone = ONBOARDING_STEP_DEFS.every(s => isOnboardingStepDone(s.key, state));
    if (allDone) { state.dismissed = true; setOnboardingState(state); return; }
    openOnboardingPage();
  }

  async function bootApp(userId) {
    checkFirstVisitToday();
    showSkeleton();
    // fetchUserRole() and loadAllData() don't actually depend on each other (RLS, not
    // client-side role checks, decides what each query returns) — they used to run one
    // after the other, adding a full extra network round trip to every single login.
    const [role] = await Promise.all([fetchUserRole(userId), loadAllData()]);
    applyUserRole(role);
    pickDashTip();
    render();
    refreshHeroCounts();
    renderContributePanel();
    if (isAdmin) renderAdminLists();
    startPresenceHeartbeat();
    startUpdatesPolling();
    startBreakWatcher();
    startMentorRequestsPolling();
    loadDirectoryEmails();
    loadCmdTechPreview();
    syncPushSubscriptionIfGranted();
    // If the Mentorship page was left open across a logout/login (a different account signing
    // in without a full page reload), its panes and any open chat thread still show the
    // previous account's data — force them to re-render against the freshly loaded data.
    if (document.getElementById('mentorshipPage').classList.contains('open')) {
      closeMentorThread();
      switchMentorTab(activeMentorTab || 'request');
    }
    // Don't let the onboarding takeover steal focus from a push-notification deep link.
    if (new URLSearchParams(window.location.search).get('mentorThread')) {
      openMentorThreadFromUrl();
    } else {
      await maybeShowOnboarding();
    }
  }

  // Deep-link support: a push-notification tap opens the site at /?mentorThread=<id> —
  // jump straight into that conversation instead of leaving the user on the home page.
  function openMentorThreadFromUrl() {
    const requestId = new URLSearchParams(window.location.search).get('mentorThread');
    if (!requestId) return;
    history.replaceState(null, '', window.location.pathname);
    openMentorshipPage();
    switchMentorTab('chats');
    openMentorThread(parseInt(requestId, 10));
  }
