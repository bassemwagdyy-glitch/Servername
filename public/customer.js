(function(){
  "use strict";

  const $ = (id) => document.getElementById(id);
  let authToken = localStorage.getItem("customer_token") || "";
  let paymentSettings = null;
  let selectedMethod = "bank_transfer";
  let selectedDuration = "month";
  let pendingOtpPhone = "";

  function showToast(msg){
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2400);
  }

  async function api(path, opts){
    opts = opts || {};
    const headers = opts.headers || {};
    headers["Content-Type"] = "application/json";
    if(authToken) headers["Authorization"] = "Bearer " + authToken;
    const res = await fetch(path, { ...opts, headers });
    if(res.status === 401){ logout(); throw new Error("unauthorized"); }
    const data = await res.json().catch(() => ({}));
    if(!res.ok){ const err = new Error(data.error || "server-error"); err.code = data.error; throw err; }
    return data;
  }

  function fmtDate(iso){
    if(!iso) return "—";
    try{ return new Date(iso).toLocaleDateString("ar-EG", { year:"numeric", month:"long", day:"numeric" }); }
    catch(e){ return iso; }
  }
  function fmtDateTime(iso){
    if(!iso) return "—";
    try{ return new Date(iso).toLocaleString("ar-EG", { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" }); }
    catch(e){ return iso; }
  }
  function daysLeft(iso){
    return Math.ceil((new Date(iso) - new Date()) / (1000*60*60*24));
  }

  /* ===================== التنقل بين الشاشات ===================== */
  function hideAllScreens(){
    $("loginScreen").style.display = "none";
    $("registerScreen").style.display = "none";
    $("otpScreen").style.display = "none";
    $("dashScreen").style.display = "none";
  }
  function showLogin(){ hideAllScreens(); $("loginScreen").style.display = "flex"; }
  function showRegister(){ hideAllScreens(); $("registerScreen").style.display = "flex"; }
  function showOtp(phone){
    hideAllScreens();
    pendingOtpPhone = phone;
    $("otpSentTo").textContent = "بعتنالك كود على " + phone;
    $("otpCode").value = "";
    $("otpError").textContent = "";
    $("otpScreen").style.display = "flex";
  }
  function showDash(){ hideAllScreens(); $("dashScreen").style.display = "block"; loadAll(); }
  function logout(){ authToken = ""; localStorage.removeItem("customer_token"); showLogin(); }

  $("btnLogout").addEventListener("click", logout);
  $("linkGoRegister").addEventListener("click", (e) => { e.preventDefault(); showRegister(); });
  $("linkGoLogin").addEventListener("click", (e) => { e.preventDefault(); showLogin(); });

  /* ===================== تسجيل الدخول ===================== */
  $("btnLogin").addEventListener("click", async () => {
    const phone = $("inPhone").value.trim();
    const password = $("inPassword").value;
    const err = $("loginError");
    err.textContent = "";
    if(!phone || !password){ err.textContent = "من فضلك املأ رقم الموبايل وكلمة السر"; return; }
    try{
      const data = await api("/api/customer/login", { method: "POST", body: JSON.stringify({ phone, password }) });
      authToken = data.token;
      localStorage.setItem("customer_token", authToken);
      showDash();
    }catch(e){
      if(e.code === "phone-not-verified"){
        err.textContent = "";
        showOtp(phone);
        showToast("رقمك لسه محتاج تأكيد — ابعتيلنا الكود اللي وصلك");
        api("/api/customer/resend-otp", { method: "POST", body: JSON.stringify({ phone }) }).catch(()=>{});
      } else {
        err.textContent = "بيانات الدخول غلط";
      }
    }
  });
  $("inPassword").addEventListener("keydown", (e) => { if(e.key === "Enter") $("btnLogin").click(); });

  /* ===================== إنشاء حساب جديد ===================== */
  $("btnRegister").addEventListener("click", async () => {
    const name = $("regName").value.trim();
    const storeName = $("regStore").value.trim();
    const phone = $("regPhone").value.trim();
    const email = $("regEmail").value.trim();
    const password = $("regPassword").value;
    const err = $("registerError");
    err.textContent = "";
    if(!name || !storeName || !phone || !password){ err.textContent = "من فضلك املأ كل الحقول المطلوبة (*)"; return; }
    if(password.length < 6){ err.textContent = "كلمة السر لازم تكون 6 أحرف على الأقل"; return; }
    try{
      await api("/api/customer/register", { method: "POST", body: JSON.stringify({ name, storeName, phone, email, password }) });
      showToast("تم إرسال كود التأكيد على رقمك");
      showOtp(phone);
    }catch(e){
      const map = { "phone-taken": "الرقم ده مسجّل بحساب موثّق بالفعل — سجّلي دخول بدل كده", "bad-phone": "رقم الموبايل مش صحيح", "weak-password": "كلمة السر قصيرة أوي" };
      err.textContent = map[e.code] || "حصل خطأ أثناء إنشاء الحساب";
    }
  });

  /* ===================== تأكيد الكود (OTP) ===================== */
  $("btnVerifyOtp").addEventListener("click", async () => {
    const code = $("otpCode").value.trim();
    const err = $("otpError");
    err.textContent = "";
    if(!code){ err.textContent = "من فضلك اكتبي الكود"; return; }
    try{
      const data = await api("/api/customer/verify-otp", { method: "POST", body: JSON.stringify({ phone: pendingOtpPhone, code }) });
      authToken = data.token;
      localStorage.setItem("customer_token", authToken);
      showToast("تم تأكيد الحساب بنجاح");
      showDash();
    }catch(e){
      const map = { "wrong-code": "الكود غلط", "otp-expired": "الكود ده منتهي، اطلبي كود جديد", "too-many-attempts": "محاولات كتير غلط — اطلبي كود جديد", "no-otp-requested": "اطلبي كود جديد الأول" };
      err.textContent = map[e.code] || "حصل خطأ أثناء التأكيد";
    }
  });
  $("otpCode").addEventListener("keydown", (e) => { if(e.key === "Enter") $("btnVerifyOtp").click(); });
  $("linkResendOtp").addEventListener("click", async (e) => {
    e.preventDefault();
    try{ await api("/api/customer/resend-otp", { method: "POST", body: JSON.stringify({ phone: pendingOtpPhone }) }); showToast("تم إرسال كود جديد"); }
    catch(e){ showToast("حصل خطأ، جربي تاني بعد شوية"); }
  });

  $("btnCopyServerUrl").addEventListener("click", () => {
    navigator.clipboard.writeText($("activationServerUrl").value).then(() => showToast("تم نسخ رابط السيرفر"));
  });
  $("btnCopyKey").addEventListener("click", () => {
    navigator.clipboard.writeText($("activationKey").value).then(() => showToast("تم نسخ المفتاح"));
  });

  /* ===================== لوحة العميل (بعد الدخول) ===================== */
  async function loadAll(){
    await loadMe();
    await loadPaymentSettings();
    await loadClaims();
  }

  async function loadMe(){
    try{
      const me = await api("/api/customer/me");
      $("storeTitle").textContent = me.storeName;
      const banner = $("statusBanner");
      const actCard = $("activationCard");
      if(!me.subscription){
        banner.className = "status-banner bad";
        banner.innerHTML = `<div class="big">⛔ مفيش اشتراك مفعّل</div><div class="detail">ادفعي أول اشتراك من تحت عشان تفعّلي الشاشة</div>`;
        actCard.style.display = "none";
      } else if(me.subscription.status === "active"){
        const left = daysLeft(me.subscription.expiresAt);
        const warn = left <= 5;
        banner.className = "status-banner " + (warn ? "warn" : "ok");
        banner.innerHTML = `<div class="big">${warn ? "⚠️ الاشتراك هينتهي قريب" : "✅ الاشتراك شغّال"}</div><div class="detail">ينتهي في ${fmtDate(me.subscription.expiresAt)} (متبقي ${left <= 0 ? 0 : left} يوم)</div>`;
        $("activationServerUrl").value = window.location.origin;
        $("activationKey").value = me.subscription.licenseKey;
        actCard.style.display = "block";
      } else if(me.subscription.status === "revoked"){
        banner.className = "status-banner bad";
        banner.innerHTML = `<div class="big">⛔ الاشتراك موقوف</div><div class="detail">تواصلي مع الدعم الفني</div>`;
        actCard.style.display = "none";
      } else {
        banner.className = "status-banner bad";
        banner.innerHTML = `<div class="big">⏳ الاشتراك منتهي</div><div class="detail">انتهى في ${fmtDate(me.subscription.expiresAt)} — جدّدي من تحت</div>`;
        actCard.style.display = "none";
      }
    }catch(e){ showToast("تعذّر تحميل البيانات"); }
  }

  async function loadPaymentSettings(){
    try{
      paymentSettings = await fetch("/api/payment-settings").then(r => r.json());
      renderPayInstructions();
    }catch(e){ $("payInstructions").textContent = "تعذّر تحميل تعليمات الدفع"; }
  }
  function renderPayInstructions(){
    if(!paymentSettings) return;
    const map = {
      bank_transfer: paymentSettings.bankDetails || "لسه مفيش بيانات تحويل بنكي متسجلة",
      vodafone_cash: paymentSettings.vodafoneCash ? ("حوّلي على رقم فودافون كاش: " + paymentSettings.vodafoneCash) : "لسه مفيش رقم فودافون كاش متسجل",
      instapay: paymentSettings.instapay ? ("حوّلي عن طريق إنستاباي: " + paymentSettings.instapay) : "لسه مفيش بيانات إنستاباي متسجلة"
    };
    $("payInstructions").textContent = map[selectedMethod];
  }
  $("payMethods").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-method]");
    if(!btn) return;
    document.querySelectorAll(".pay-method-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    selectedMethod = btn.dataset.method;
    renderPayInstructions();
  });
  $("durGrid").addEventListener("click", (e) => {
    const btn = e.target.closest(".dur-btn");
    if(!btn) return;
    document.querySelectorAll(".dur-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    selectedDuration = btn.dataset.dur;
  });

  $("btnSubmitClaim").addEventListener("click", async () => {
    const err = $("claimError");
    err.textContent = "";
    try{
      await api("/api/customer/payment-claims", {
        method: "POST",
        body: JSON.stringify({
          method: selectedMethod,
          duration: selectedDuration,
          amount: $("inAmount").value.trim(),
          reference: $("inReference").value.trim()
        })
      });
      showToast("تم إرسال طلبك، هيتم التفعيل بعد المراجعة");
      $("inAmount").value = ""; $("inReference").value = "";
      loadClaims();
    }catch(e){ err.textContent = "حصل خطأ أثناء الإرسال"; }
  });

  async function loadClaims(){
    const body = $("claimsBody");
    try{
      const data = await api("/api/customer/payment-claims");
      body.innerHTML = "";
      if(data.claims.length === 0){
        body.innerHTML = '<tr class="empty-row"><td colspan="4">لسه معملتيش أي طلب دفع</td></tr>';
        return;
      }
      const methodNames = { bank_transfer: "تحويل بنكي", vodafone_cash: "فودافون كاش", instapay: "إنستاباي" };
      const durNames = { day:"يوم", "3days":"3 أيام", week:"أسبوع", month:"شهر", "3months":"3 شهور", "6months":"6 شهور", year:"سنة" };
      const statusMap = { pending: ["قيد المراجعة","warn"], approved: ["تم القبول","ok"], rejected: ["مرفوض","bad"] };
      data.claims.forEach(c => {
        const [label, cls] = statusMap[c.status] || [c.status, "warn"];
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${fmtDateTime(c.submittedAt)}</td>
          <td>${methodNames[c.method] || c.method}</td>
          <td>${durNames[c.duration] || c.duration}</td>
          <td><span class="status-pill ${cls}">${label}</span></td>`;
        body.appendChild(tr);
      });
    }catch(e){ showToast("تعذّر تحميل سجل الطلبات"); }
  }

  if(authToken) showDash(); else showLogin();
})();
