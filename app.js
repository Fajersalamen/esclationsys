/* ============================================================
   Nova — Customer Service Scripts (FAJER AL SALAMEEN)
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

  document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    hideLoginError();
    const email = document.getElementById('loginEmail').value.trim();
    const pass = document.getElementById('loginPassword').value;
    const btn = document.getElementById('loginSubmitBtn');
    const spinner = document.getElementById('loginSpinner');
    const text = document.getElementById('loginSubmitText');
    btn.disabled = true;
    spinner.style.display = 'inline-block';
    text.style.opacity = '0.6';
    sb.auth.signInWithPassword({ email, password: pass })
      .then(({ error }) => {
        if (error) showLoginError(authErrorMessage(error.message));
      })
      .finally(() => {
        btn.disabled = false;
        spinner.style.display = 'none';
        text.style.opacity = '1';
      });
  });

  document.getElementById('loginForgotBtn').addEventListener('click', function () {
    const email = document.getElementById('loginEmail').value.trim();
    if (!email) {
      showLoginError('Enter your email above first, then click "Forgot password" again.');
      return;
    }
    sb.auth.resetPasswordForEmail(email)
      .then(({ error }) => {
        if (error) showLoginError(authErrorMessage(error.message));
        else showLoginError('✅ A reset link was sent to your email.');
      });
  });

  function employeeLogout() {
    closeProfileMenu();
    stopPresenceHeartbeat();
    stopPresenceAdminRefresh();
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
    const isOpen = dd.classList.toggle('open');
    btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }
  function closeProfileMenu() {
    document.getElementById('profileDropdown').classList.remove('open');
    document.getElementById('profileBtn').setAttribute('aria-expanded', 'false');
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
    }
  });
  // ====== End Supabase Authentication ======

  // ====== Decorative animated "typing" chat bubbles on the login image panel ======
  (function () {
    const track = document.getElementById('chatBubbleTrack');
    if (!track) return;

    const SCRIPT = [
      { side: 'agent',   text: 'Hi there 👋' },
      { side: 'client',  text: 'How can I help you today?' },
      { side: 'agent',   text: 'I have a question about my order' },
      { side: 'client',  text: 'Your order has been received ✅' },
      { side: 'agent',   text: 'Thanks for the quick response 🙏' },
      { side: 'client',  text: 'Our team is always here to help' },
    ];

    const MAX_VISIBLE = 4;
    const TYPE_SPEED_MS = 42;
    const PAUSE_AFTER_TYPE_MS = 1100;
    const PAUSE_BETWEEN_MS = 450;
    const LOOP_PAUSE_MS = 1400;

    let cancelled = false;
    let visibleBubbles = [];

    function sleep(ms) {
      return new Promise(function (resolve) { setTimeout(resolve, ms); });
    }

    async function typeIntoBubble(bubbleEl, text) {
      const textSpan = document.createElement('span');
      const caret = document.createElement('span');
      caret.className = 'chat-caret';
      bubbleEl.appendChild(textSpan);
      bubbleEl.appendChild(caret);

      requestAnimationFrame(function () { bubbleEl.classList.add('show'); });

      for (let i = 0; i < text.length; i++) {
        if (cancelled) return;
        textSpan.textContent += text[i];
        await sleep(TYPE_SPEED_MS);
      }
      caret.remove();
    }

    async function runLoop() {
      while (!cancelled) {
        for (let i = 0; i < SCRIPT.length; i++) {
          if (cancelled) return;
          const msg = SCRIPT[i];
          const bubble = document.createElement('div');
          bubble.className = 'chat-bubble' + (msg.side === 'agent' ? ' from-agent' : '');
          track.appendChild(bubble);
          visibleBubbles.push(bubble);

          if (visibleBubbles.length > MAX_VISIBLE) {
            const old = visibleBubbles.shift();
            old.classList.add('fade-out');
            setTimeout(function () { old.remove(); }, 500);
          }

          await typeIntoBubble(bubble, msg.text);
          if (cancelled) return;
          await sleep(PAUSE_AFTER_TYPE_MS);
          await sleep(PAUSE_BETWEEN_MS);
        }
        if (cancelled) return;
        await sleep(LOOP_PAUSE_MS);
        visibleBubbles.forEach(function (b) { b.classList.add('fade-out'); });
        await sleep(500);
        track.innerHTML = '';
        visibleBubbles = [];
      }
    }

    runLoop();
  })();
  // ====== End chat bubbles animation ======


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

  // يجيب كل بيانات المشروع من Supabase مرة وحدة بعد تسجيل الدخول
  async function loadAllData() {
    const [catRes, scrRes, genRes, critRes, etiqRes, updRes] = await Promise.all([
      sb.from('categories').select('*').order('created_at', { ascending: true }),
      sb.from('scripts').select('*').order('id', { ascending: true }),
      sb.from('general_info').select('*').order('id', { ascending: true }),
      sb.from('critical_items').select('*').order('id', { ascending: true }),
      sb.from('etiquette_items').select('*').order('id', { ascending: true }),
      sb.from('updates').select('*').order('id', { ascending: false })
    ]);

    CATEGORIES = catRes.error ? DEFAULT_CATEGORIES : (catRes.data || []).map(c => ({ key: c.key, label: c.label, labelAr: c.label_ar, color: c.color }));
    SCRIPTS = scrRes.error ? DEFAULT_SCRIPTS : (scrRes.data || []).map(s => ({ id: s.id, cat: s.cat, title: s.title, titleAr: s.title_ar, text: s.text, textAr: s.text_ar, usageCount: s.usage_count || 0 }));
    GENERAL_INFO = genRes.error ? DEFAULT_GENERAL_INFO : (genRes.data || []).map(g => ({ id: g.id, label: g.label, labelAr: g.label_ar, val: g.val, valAr: g.val_ar }));
    CRITICAL_ITEMS = critRes.error ? DEFAULT_CRITICAL_ITEMS.map(t => ({ text: t })) : (critRes.data || []).map(c => ({ id: c.id, text: c.text, textAr: c.text_ar }));
    ETIQUETTE_ITEMS = etiqRes.error ? DEFAULT_ETIQUETTE_ITEMS.map(t => ({ text: t })) : (etiqRes.data || []).map(e => ({ id: e.id, text: e.text, textAr: e.text_ar }));
    UPDATES = updRes.error ? [] : (updRes.data || []).map(u => ({ id: u.id, text: u.text, createdAt: new Date(u.created_at).getTime() }));

    // الاقتراحات يشوفها بس اللي عندهم صلاحية admin/team_leader
    if (isAdmin) {
      const sugRes = await sb.from('suggestions').select('*').order('id', { ascending: false });
      SUGGESTIONS = sugRes.error ? [] : (sugRes.data || []).map(s => ({ id: s.id, name: s.name, text: s.text, createdAt: new Date(s.created_at).getTime() }));
    } else {
      SUGGESTIONS = [];
    }

    // بيانات مركز التدريب (Dynamic) — يتم تحميلها لكل المستخدمين (RLS بتحدد شو يوصلهم فعلياً)
    await loadTrainingData();
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
      const { data: { user } } = await sb.auth.getUser();
      const uid = user && user.id;
      if (!uid) return;
      if (isNewSession || !currentSessionStartedAt) currentSessionStartedAt = new Date().toISOString();
      const { error } = await sb.from('user_presence').upsert({
        user_id: uid,
        email: currentUserEmail,
        session_started_at: currentSessionStartedAt,
        last_seen: new Date().toISOString()
      }, { onConflict: 'user_id' });
      if (error) console.warn('تعذّر تحديث حالة الاتصال (presence):', error.message);
    } catch (err) {
      console.warn('presence heartbeat error:', err);
    }
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

    body.innerHTML = PRESENCE_USERS.map(u => {
      const statusText = u.isOnline ? (isAr ? 'متصل' : 'Online') : (isAr ? 'غير متصل' : 'Offline');
      const lastActiveText = timeFn(now - new Date(u.lastSeen).getTime());
      const loginTimeText = u.isOnline ? loginTimeFmt(u.sessionStartedAt) : '—';
      const initials = (u.email || '؟').trim().slice(0, 2).toUpperCase();
      return `<tr>
        <td><span class="presence-dot ${u.isOnline ? 'on' : 'off'}" title="${escapeHtml(statusText)}"></span></td>
        <td><span class="presence-user" title="${escapeHtml(u.email || '')}">${escapeHtml(u.email || initials)}</span></td>
        <td><span class="presence-status-pill ${u.isOnline ? 'on' : 'off'}">${statusText}</span></td>
        <td class="presence-time">${lastActiveText}</td>
        <td class="presence-time">${loginTimeText}</td>
      </tr>`;
    }).join('');
  }
  // ===================== End Online Users (Presence) =====================

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
    closeToolsOverlay();
    closeTechPage();
    document.getElementById('trainingPage').classList.add('open');
    backToTrainingGrid();
  }
  function closeTrainingPage() {
    document.getElementById('trainingPage').classList.remove('open');
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

    document.getElementById('langBtnText').textContent = isAr ? 'English' : 'العربية';
    document.getElementById('logoutBtnText').textContent = isAr ? 'خروج' : 'Logout';
    document.getElementById('profileRoleLabel').textContent = isAr ? 'موظف' : 'Employee';
    document.getElementById('profileDecorLabel').textContent = isAr ? 'الإعدادات والمظهر' : 'Settings & Appearance';
    document.getElementById('searchInput').placeholder = isAr ? 'البحث بالعنوان أو محتوى الرد...' : 'Search by title or response content...';
    document.getElementById('workspaceTitle').textContent = isAr ? 'تصعيد التذكرة' : 'Escalation Ticket';
    document.getElementById('scriptCountLabel').textContent = isAr ? 'سكريبت متاح' : 'available scripts';
    
    const lblQt = document.getElementById('lblQuickTools');
    if (lblQt) lblQt.textContent = isAr ? 'أدوات سريعة' : 'QUICK TOOLS';
    document.getElementById('lblSideGen').textContent = isAr ? 'معلومات عامة' : 'GENERAL INFO';
    document.getElementById('lblSideCrit').textContent = isAr ? 'أخطاء حرجة' : 'CRITICAL MISTAKES';
    document.getElementById('lblSideEtiq').textContent = isAr ? 'بروتوكول المكالمة' : 'ETIQUETTE CALL';
    document.getElementById('lblSideUpdate').textContent = isAr ? 'تحديثات جديدة' : 'NEW UPDATE';
    document.getElementById('lblSideSuggest').textContent = isAr ? 'الاقتراحات' : 'SUGGESTIONS';

    document.getElementById('hGenInfo').textContent = isAr ? 'ℹ️ معلومات عامة' : 'ℹ️ General Information';
    document.getElementById('hEtiqCall').textContent = isAr ? '📞 بروتوكول المكالمة' : '📞 Etiquette Call';
    document.getElementById('hCritMist').textContent = isAr ? '⚠ الأخطاء الحرجة' : '⚠ Critical Mistakes';
    document.getElementById('hNewUpdate').textContent = isAr ? '🔔 التحديثات الجديدة' : '🔔 New Updates';
    document.getElementById('lblUpdDesc').textContent = isAr ? 'أضف تحديثاً جديداً — سيظهر إشعار للفريق تلقائياً:' : 'Add a new update — the team gets a notification automatically:';
    document.getElementById('btnAddUpd').textContent = isAr ? '🔔 نشر التحديث للفريق' : '🔔 Publish Update to Team';

    document.getElementById('hSuggest').textContent = isAr ? '💡 اقتراح جديد' : '💡 New Suggestion';
    document.getElementById('lblSuggestDesc').textContent = isAr ? 'شاركنا اقتراحك لتحسين العمل — يصل مباشرة للإدارة فقط.' : 'Share your suggestion to improve the work — it goes straight to management only.';
    document.getElementById('lblSuggestAs').textContent = isAr ? 'سيصل الاقتراح باسم:' : 'Will be sent as:';
    document.getElementById('suggestText').placeholder = isAr ? 'اكتب اقتراحك هنا...' : 'Write your suggestion here...';
    document.getElementById('btnSubmitSuggest').textContent = isAr ? 'إرسال الاقتراح' : 'Submit Suggestion';
    document.getElementById('lblSuggAdminDesc').textContent = isAr ? 'اقتراحات الموظفين — تظهر هنا فقط ولا يراها أحد غيرك:' : "Employee suggestions — visible only here, no one else can see them:";

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
    document.getElementById('techPageTitle').textContent = isAr ? '🛠️ مشاكل تقنية' : '🛠️ Technical Issues';
    document.getElementById('techLiveLabel').textContent = isAr ? 'مباشر' : 'Live';
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
    if (TECH_ISSUES.length) renderTechSheet();

    // Hero carousel
    const heroText = {
      nvhHeadA: ['أدواتك كلها', 'Everything'],
      nvhHeadB: ['بمكان واحد', 'in one place'],
      nvhTag1: ['الصفحة الرئيسية', 'Home'],
      nvhTitle1: ['مكتبة السكريبتات', 'Script Library'],
      nvhSub1: ['تصعيد · متابعة · إغلاق التذكرة', 'Escalation · Follow-up · Closing'],
      nvhTag2: ['الدعم الفني', 'Support'],
      nvhMeta2: ['مباشر ●', 'Live ●'],
      nvhTitle2: ['مشاكل تقنية', 'Technical Issues'],
      nvhSub2: ['سجّل العطل وتابع الحالة لحظياً', 'Log an issue, track it live'],
      nvhTag3: ['التطوير', 'Development'],
      nvhTitle3: ['مركز التدريب', 'Training Center'],
      nvhSub3: ['سيناريوهات تفاعلية خطوة بخطوة', 'Interactive step-by-step scenarios'],
      nvhTag4: ['أدوات سريعة', 'Quick Tools'],
      nvhMeta4: ['5 أدوات', '5 tools'],
      nvhTitle4: ['معلومات وأدوات', 'Info & Tools'],
      nvhSub4: ['أخطاء حرجة · آداب المكالمة · تحديثات', 'Critical mistakes · Etiquette · Updates']
    };
    Object.keys(heroText).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = isAr ? heroText[id][0] : heroText[id][1];
    });
    refreshHeroCounts();
    if (novaHeroLayout) novaHeroLayout();

    // Quick-tools overlay
    const toolsText = {
      toolsOverlayTitle: ['أدوات سريعة', 'Quick Tools'],
      toolsOverlaySub: ['كل الأدوات المساعدة بمكان واحد', 'Every helper tool in one place'],
      lblToolTagGen: ['معلومات', 'Info'],
      lblToolTagCrit: ['تحذير', 'Warning'],
      lblToolTagEtiq: ['بروتوكول', 'Protocol'],
      lblToolTagUpd: ['جديد', 'New'],
      lblToolTagSug: ['شاركنا', 'Share']
    };
    Object.keys(toolsText).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = isAr ? toolsText[id][0] : toolsText[id][1];
    });

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

    updateThemeIcon();
  }

  function updateThemeIcon() {
    const isDark = document.body.classList.contains('dark-mode');
    const isAr = (typeof currentLang !== 'undefined') && currentLang === 'ar';
    const shortLabel = isDark ? (isAr ? 'الوضع الفاتح' : 'Light Mode') : (isAr ? 'الوضع الداكن' : 'Dark Mode');
    const themeTextEl = document.getElementById('profileThemeText');
    const themeIconEl = document.getElementById('profileThemeIcon');
    if (themeTextEl) themeTextEl.textContent = shortLabel;
    if (themeIconEl) themeIconEl.textContent = isDark ? '☀️' : '🌙';
  }

  function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('fajer_dark_mode', document.body.classList.contains('dark-mode'));
    updateThemeIcon();
  }

  if (localStorage.getItem('fajer_dark_mode') !== 'false') {
    document.body.classList.add('dark-mode');
  }
  updateThemeIcon();

  // ====== Orbit-field animated background: drifting particles with proximity links ======
  function initOrbitField(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const colors = ['#0B84FF', '#14B8A6', '#10B981'];
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    let W, H, points = [];

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
    }
    function step() {
      ctx.clearRect(0, 0, W, H);
      for (const p of points) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }
      for (let i = 0; i < points.length; i++) {
        for (let j = i + 1; j < points.length; j++) {
          const a = points[i], b = points[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.strokeStyle = `rgba(20,184,166,${0.16 * (1 - dist / 120)})`;
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
    seed();
    window.addEventListener('resize', seed);
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      requestAnimationFrame(step);
    }
  }
  ['orbitCanvasHome', 'orbitCanvasTech', 'orbitCanvasTraining'].forEach(initOrbitField);

  // ====== Hero: 3D rotating carousel of the site's sections ======
  let novaHeroTimer = null;
  let novaHeroLayout = null;
  function setupNovaHero() {
    const heroSection = document.getElementById('novaHero');
    const track = document.getElementById('nvhTrack');
    const dotsWrap = document.getElementById('nvhDots');
    if (!track || !dotsWrap) return;
    const slides = Array.from(track.querySelectorAll('.nvh-slide'));
    if (!slides.length) return;
    let active = 0;

    dotsWrap.innerHTML = '';
    slides.forEach((s, i) => {
      const d = document.createElement('button');
      d.type = 'button';
      const label = s.querySelector('.nvh-title');
      d.setAttribute('aria-label', label ? label.textContent : String(i + 1));
      d.addEventListener('click', () => { active = i; layout(); restart(); });
      dotsWrap.appendChild(d);
    });
    const dots = Array.from(dotsWrap.children);

    function layout() {
      const n = slides.length;
      const fan = window.innerWidth <= 720 ? 74 : 128;
      slides.forEach((s, i) => {
        let off = i - active;
        if (off > n / 2) off -= n;
        if (off < -n / 2) off += n;
        const abs = Math.abs(off);
        s.style.transform =
          `translateX(${off * fan}px) translateZ(${-abs * 150}px) rotateY(${off * -30}deg) scale(${1 - abs * 0.08})`;
        s.style.opacity = abs > 2 ? '0' : (off === 0 ? '1' : '0.8');
        s.style.filter = off === 0 ? 'none' : 'brightness(.62)';
        s.style.zIndex = String(50 - abs);
        s.style.pointerEvents = abs > 2 ? 'none' : 'auto';
      });
      dots.forEach((d, i) => d.classList.toggle('on', i === active));
    }
    novaHeroLayout = layout;

    function restart() {
      clearInterval(novaHeroTimer);
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      novaHeroTimer = setInterval(() => { active = (active + 1) % slides.length; layout(); }, 3600);
    }

    slides.forEach((s, i) => {
      s.addEventListener('click', () => {
        if (i !== active) { active = i; layout(); restart(); return; }
        goToHeroSection(s.dataset.go);
      });
    });

    // Scrolling anywhere over the hero (not just the narrow card stack) steps through the
    // slides instead of scrolling the page — matches the whole "Every tool in one place" section.
    let wheelLock = false;
    (heroSection || track).addEventListener('wheel', (e) => {
      e.preventDefault();
      if (wheelLock) return;
      wheelLock = true;
      active = (active + (e.deltaY > 0 ? 1 : -1) + slides.length) % slides.length;
      layout();
      restart();
      setTimeout(() => { wheelLock = false; }, 450);
    }, { passive: false });

    layout();
    window.addEventListener('resize', layout);
    restart();
  }

  // ====== Quick-tools overlay: vertical auto-rotating fan (mirrors setupNovaHero, but on the vertical axis) ======
  let toolsFanCtrl = null;
  function setupToolsFan() {
    const fan = document.getElementById('toolsFan');
    const dotsWrap = document.getElementById('toolsFanDots');
    if (!fan || !dotsWrap) return null;
    const cards = Array.from(fan.querySelectorAll('.tool-card'));
    if (!cards.length) return null;
    const n = cards.length;
    let active = 0;
    let timer = null;
    const gridQuery = window.matchMedia('(max-width: 860px)');

    dotsWrap.innerHTML = '';
    cards.forEach(() => dotsWrap.appendChild(document.createElement('span')));
    const dots = Array.from(dotsWrap.children);

    function layout() {
      if (gridQuery.matches) {
        cards.forEach(c => {
          c.style.transform = ''; c.style.opacity = ''; c.style.filter = '';
          c.style.zIndex = ''; c.style.pointerEvents = '';
        });
        dots.forEach(d => d.classList.remove('on'));
        return;
      }
      const fanY = window.innerWidth <= 720 ? 74 : 118;
      cards.forEach((card, i) => {
        let off = i - active;
        if (off > n / 2) off -= n;
        if (off < -n / 2) off += n;
        const abs = Math.abs(off);
        card.style.transform =
          `translateY(${off * fanY}px) translateZ(${-abs * 150}px) rotateX(${off * 22}deg) scale(${1 - abs * 0.1})`;
        card.style.opacity = abs > 2 ? '0' : (off === 0 ? '1' : String(0.85 - abs * 0.12));
        card.style.filter = off === 0 ? 'none' : 'brightness(.6)';
        card.style.zIndex = String(50 - abs);
        card.style.pointerEvents = abs > 2 ? 'none' : 'auto';
      });
      dots.forEach((d, i) => d.classList.toggle('on', i === active));
    }

    function stop() { clearInterval(timer); timer = null; }
    function start() {
      stop();
      if (gridQuery.matches || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      timer = setInterval(() => { active = (active + 1) % n; layout(); }, 3600);
    }

    // Scrolling over the fan steps through the cards instead of scrolling the page behind it.
    let wheelLock = false;
    fan.addEventListener('wheel', (e) => {
      if (gridQuery.matches) return;
      e.preventDefault();
      if (wheelLock) return;
      wheelLock = true;
      active = (active + (e.deltaY > 0 ? 1 : -1) + n) % n;
      layout();
      start();
      setTimeout(() => { wheelLock = false; }, 450);
    }, { passive: false });

    layout();
    window.addEventListener('resize', layout);
    gridQuery.addEventListener('change', () => { layout(); start(); });

    return { layout, start, stop };
  }

  function openToolsOverlay() {
    const ov = document.getElementById('toolsOverlay');
    if (!ov) return;
    ov.classList.add('open');
    ov.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    if (!toolsFanCtrl) toolsFanCtrl = setupToolsFan();
    if (toolsFanCtrl) { toolsFanCtrl.layout(); toolsFanCtrl.start(); }
  }
  function closeToolsOverlay() {
    const ov = document.getElementById('toolsOverlay');
    if (!ov) return;
    ov.classList.remove('open', 'behind');
    ov.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (toolsFanCtrl) toolsFanCtrl.stop();
  }
  // Keep the Quick Tools fan visible (dimmed, non-interactive) behind a panel opened from it,
  // instead of dropping all the way back to the home page.
  function sendToolsOverlayBehind() {
    const ov = document.getElementById('toolsOverlay');
    if (!ov) return;
    ov.classList.add('behind');
    ov.setAttribute('aria-hidden', 'true');
    if (toolsFanCtrl) toolsFanCtrl.stop();
  }
  function bringToolsOverlayFront() {
    const ov = document.getElementById('toolsOverlay');
    if (!ov) return;
    ov.classList.remove('behind');
    ov.setAttribute('aria-hidden', 'false');
    if (toolsFanCtrl) { toolsFanCtrl.layout(); toolsFanCtrl.start(); }
  }

  function goToHeroSection(key) {
    if (key === 'tech') { openTechPage(); return; }
    if (key === 'training') { openTrainingPage(); return; }
    if (key === 'tools') { openToolsOverlay(); return; }
    const controls = document.querySelector('.controls');
    if (controls) controls.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Keeps the hero cards' counters in sync with the real data.
  function refreshHeroCounts() {
    const isAr = currentLang === 'ar';
    const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
    set('nvhMeta1', SCRIPTS.length ? (isAr ? `${SCRIPTS.length} سكريبت` : `${SCRIPTS.length} scripts`) : '—');
    set('nvhMeta3', TRAINING_PROBLEMS.length
      ? (isAr ? `${TRAINING_PROBLEMS.length} مواضيع` : `${TRAINING_PROBLEMS.length} topics`)
      : '—');
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

    const sortedUpdates = [...UPDATES].sort((a, b) => b.id - a.id);
    const updList = document.getElementById('newUpdateList');
    if (!sortedUpdates.length) {
      updList.innerHTML = `<div class="info-card" style="border-inline-start-color:#5b3fb0;">${isAr ? 'لا توجد تحديثات حالياً.' : 'No updates yet.'}</div>`;
    } else {
      const ARCHIVE_MS = UPDATE_ARCHIVE_DAYS * 24 * 60 * 60 * 1000;
      const cutoff = Date.now() - ARCHIVE_MS;
      const recentUpdates = sortedUpdates.filter(u => u.createdAt >= cutoff);
      const archivedUpdates = sortedUpdates.filter(u => u.createdAt < cutoff);
      const renderCard = u => {
        const dateStr = new Date(u.createdAt).toLocaleString(isAr ? 'ar' : 'en', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
        return `<div class="update-card"><div class="update-top"><span class="update-date">${dateStr}</span></div><div class="update-text">${escapeHtml(u.text)}</div></div>`;
      };
      let html = recentUpdates.length
        ? recentUpdates.map(renderCard).join('')
        : `<div class="info-card" style="border-inline-start-color:#5b3fb0;">${isAr ? 'لا توجد تحديثات حديثة.' : 'No recent updates.'}</div>`;
      if (archivedUpdates.length) {
        const archiveLabel = isAr ? `📁 أرشيف التحديثات القديمة (${archivedUpdates.length})` : `📁 Archived Updates (${archivedUpdates.length})`;
        html += `<details class="update-archive"><summary>${archiveLabel}</summary>${archivedUpdates.map(renderCard).join('')}</details>`;
      }
      updList.innerHTML = html;
    }
    updateNotificationBadge();
  }

  function updateNotificationBadge() {
    const lastSeen = parseInt(localStorage.getItem('fajer_updates_seen_v2') || '0', 10);
    const unseenCount = UPDATES.filter(u => u.id > lastSeen).length;
    const label = unseenCount > 9 ? '9+' : String(unseenCount);
    [document.getElementById('updateBadge'), document.getElementById('nvhToolsBadge')].forEach(badge => {
      if (!badge) return;
      if (unseenCount > 0) {
        badge.textContent = label;
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }
    });
  }

  async function addUpdate() {
    const isAr = currentLang === 'ar';
    const text = document.getElementById('newUpdText').value.trim();
    if (!text) return;
    const { data, error } = await sb.from('updates').insert({ text }).select().single();
    if (error) {
      showToast(isAr ? 'تعذّر نشر التحديث.' : 'Could not publish the update.', 'error');
      return;
    }
    UPDATES.push({ id: data.id, text: data.text, createdAt: new Date(data.created_at).getTime() });
    document.getElementById('newUpdText').value = '';
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

  function checkFirstVisitToday() {
    const splash = document.getElementById('splashOverlay');
    if (!splash) return;
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
        closePanels();
        closeAdminModal();
        closeTechPage();
        closeTrainingPage();
        closeToolsOverlay();
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

  function canDelete() {
    if (adminRole === 'full') return true;
    showToast(currentLang === 'ar' ? 'ما عندك صلاحية الحذف — راجع المشرف الكامل.' : "You don't have delete permission — contact the full admin.", 'error');
    return false;
  }

  function setCategory(cat) { activeCat = cat; render(); }

  // ===================== Technical Issue (شريط سفلي — مشاكل تقنية) =====================
  // البيانات مشتركة بين كل الموظفين عبر جدول technical_issues على Supabase.
  let TECH_ISSUES = [];
  let techAttachedNumber = null;

  const TECH_ISSUE_LABELS = {
    audio:  { ar: '🔇 الصوت بالمكالمة مشوش', en: '🔇 Audio is unclear' },
    closed: { ar: '📴 تم إغلاق المكالمة',     en: '📴 Call got disconnected' },
    delay:  { ar: '⏱️ تأخير في المكالمة',      en: '⏱️ Delay in the call' }
  };

  function goHome() {
    closePanels();
    closeToolsOverlay();
    closeTechPage();
    closeTrainingPage();
    closeAdminModal();
    setCategory(null);
    const searchEl = document.getElementById('searchInput');
    if (searchEl) searchEl.value = '';
    render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function openTechPage() {
    closePanels();
    closeToolsOverlay();
    closeTrainingPage();
    resetTechForm();
    document.getElementById('techPage').classList.add('open');
    const searchEl = document.getElementById('techRecordSearch');
    if (searchEl) searchEl.value = '';
    showTechSkeleton();
    loadTechIssues();
  }

  function closeTechPage() {
    document.getElementById('techPage').classList.remove('open');
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

  function renderTechSheet() {
    const isAr = currentLang === 'ar';
    const body = document.getElementById('techSheetBody');
    const empty = document.getElementById('techSheetEmpty');
    const countEl = document.getElementById('techSheetCount');
    const filtered = getFilteredTechIssues();

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
        <button class="copy-btn" type="button">${iconCopy}${copyTxt}</button>
        ${index >= 0 ? `
          <button class="edit-btn" data-edit-idx="${index}">${iconEdit}${editTxt}</button>
          <button class="delete-btn" data-del-idx="${index}">${iconDelete}${delTxt}</button>
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

    btn.innerHTML = iconCheck + (isAr ? 'تم النسخ!' : 'Copied!');
    btn.classList.add('copied');
    setTimeout(() => {
      btn.innerHTML = iconCopy + (isAr ? 'نسخ النص' : 'Copy Text');
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

  function updateAdminRoleLabel() {
    const isAr = currentLang === 'ar';
    const el = document.getElementById('lblAdminActive');
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
    document.getElementById('adminTabScripts').style.display = type === 'scripts' ? 'block' : 'none';
    document.getElementById('adminTabCategories').style.display = type === 'categories' ? 'block' : 'none';
    document.getElementById('adminTabPanels').style.display = type === 'panels' ? 'block' : 'none';
    document.getElementById('adminTabUpdates').style.display = type === 'updates' ? 'block' : 'none';
    document.getElementById('adminTabSuggestions').style.display = type === 'suggestions' ? 'block' : 'none';
    document.getElementById('adminTabPresence').style.display = type === 'presence' ? 'block' : 'none';
    document.getElementById('adminTabTraining').style.display = type === 'training' ? 'block' : 'none';

    document.getElementById('btnTab1').classList.toggle('active', type === 'scripts');
    document.getElementById('btnTab2').classList.toggle('active', type === 'categories');
    document.getElementById('btnTab3').classList.toggle('active', type === 'panels');
    document.getElementById('btnTab4').classList.toggle('active', type === 'updates');
    document.getElementById('btnTab5').classList.toggle('active', type === 'suggestions');
    document.getElementById('btnTab6').classList.toggle('active', type === 'presence');
    document.getElementById('btnTab7').classList.toggle('active', type === 'training');

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
      document.getElementById('saveScriptBtn').textContent = '+ إضافة السكريبت';
    } else {
      const { data, error } = await sb.from('scripts').insert({ ...payload, usage_count: 0 }).select().single();
      if (error) {
        showToast(isAr ? 'تعذّر إضافة السكريبت.' : 'Could not add the script.', 'error');
        return;
      }
      SCRIPTS.push({ id: data.id, cat: data.cat, title: data.title, titleAr: data.title_ar, text: data.text, textAr: data.text_ar, usageCount: 0 });
    }
    document.getElementById('newScriptTitle').value = '';
    document.getElementById('newScriptTitleAr').value = '';
    document.getElementById('newScriptText').value = '';
    document.getElementById('newScriptTextAr').value = '';
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
        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(u.text)}</span>
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
  }

  let panelOpenedFromTools = false;
  function openPanel(type, opts) {
    panelOpenedFromTools = !!(opts && opts.fromTools);
    if (panelOpenedFromTools) sendToolsOverlayBehind();
    else closeToolsOverlay();
    document.getElementById('overlay').classList.add('show');
    document.getElementById(type + 'Panel').classList.add('open');
    if (type === 'newUpdate') {
      const latestId = UPDATES.reduce((max, u) => Math.max(max, u.id), 0);
      localStorage.setItem('fajer_updates_seen_v2', String(latestId));
      updateNotificationBadge();
    }
  }
  // Plain close: used by page-navigation cleanup (goHome, openTechPage, Escape, ...) — never re-opens Quick Tools.
  function closePanels() {
    panelOpenedFromTools = false;
    document.getElementById('overlay').classList.remove('show');
    document.querySelectorAll('.side-panel').forEach(p => p.classList.remove('open'));
  }
  // User-initiated close (X button / backdrop click): returns to the Quick Tools list if the panel came from there.
  function closePanelsByUser() {
    const returnToTools = panelOpenedFromTools;
    closePanels();
    if (returnToTools) bringToolsOverlayFront();
  }

  // ===== ربط كل الأحداث برمجيًا (بدون onclick= داخل HTML) — مطلوب لتفعيل CSP بدون 'unsafe-inline' لـ script-src =====
  function bindStaticEvents() {
    const on = (id, evt, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(evt, fn); };

    document.querySelector('.qt-general').addEventListener('click', () => openPanel('general', { fromTools: true }));
    document.querySelector('.qt-critical').addEventListener('click', () => openPanel('critical', { fromTools: true }));
    document.querySelector('.qt-etiquette').addEventListener('click', () => openPanel('etiquette', { fromTools: true }));
    document.querySelector('.qt-update').addEventListener('click', () => openPanel('newUpdate', { fromTools: true }));
    document.querySelector('.qt-suggest').addEventListener('click', () => openPanel('suggest', { fromTools: true }));

    on('overlay', 'click', closePanelsByUser);
    document.querySelectorAll('.panel-close').forEach(btn => btn.addEventListener('click', closePanelsByUser));

    on('btnSubmitSuggest', 'click', submitSuggestion);

    document.querySelectorAll('.admin-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchAdminTab(btn.dataset.adminTab));
    });

    on('saveScriptBtn', 'click', saveScript);
    on('btnAddCat', 'click', addCategory);
    on('btnAddGen', 'click', addGeneralInfo);
    on('btnAddEtiq', 'click', addEtiquette);
    on('btnAddCrit', 'click', addCritical);
    on('btnAddUpd', 'click', addUpdate);
    on('btnCloseAdmin', 'click', closeAdminModal);

    on('novaWordmark', 'dblclick', openAdminModal);
    on('profileBtn', 'click', toggleProfileMenu);
    on('profileThemeBtn', 'click', toggleTheme);
    on('profileLangBtn', 'click', toggleLanguage);
    on('logoutBtn', 'click', employeeLogout);
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

    // الشريط السفلي الثابت
    on('bbHomeBtn', 'click', () => { launchHomePlanet(); goHome(); });
    on('toolsCloseBtn', 'click', closeToolsOverlay);
    on('toolsOverlay', 'click', (e) => { if (e.target && e.target.id === 'toolsOverlay') closeToolsOverlay(); });

    // صفحة المشاكل التقنية
    on('techBackBtn', 'click', closeTechPage);
    on('techAttachBtn', 'click', attachTechNumber);
    on('techChangeNumBtn', 'click', changeTechNumber);
    on('techNumberInput', 'keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); attachTechNumber(); } });
    on('techRecordSearch', 'input', renderTechSheet);
    document.querySelectorAll('.tech-opt-btn').forEach(btn => {
      btn.addEventListener('click', () => submitTechIssue(btn.dataset.issue));
    });
    document.getElementById('techSheetBody').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-del-tech]');
      if (btn) deleteTechIssue(parseInt(btn.dataset.delTech, 10));
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
  setupNovaHero();

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

  async function bootApp(userId) {
    checkFirstVisitToday();
    showSkeleton();
    const role = await fetchUserRole(userId);
    applyUserRole(role);
    await loadAllData();
    pickDashTip();
    render();
    refreshHeroCounts();
    if (isAdmin) renderAdminLists();
    startPresenceHeartbeat();
  }
