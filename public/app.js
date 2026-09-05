(function(){
  "use strict";

  const $ = (id) => document.getElementById(id);
  const API = ""; // نفس الأصل (السيرفر بيخدم الواجهة والـ API مع بعض)
  let authToken = localStorage.getItem("admin_token") || "";

  function showToast(msg){
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2400);
  }

  async function api(path, opts){
    opts = opts || {};
    const headers = opts.headers || {};
    if(!(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
    if(authToken) headers["Authorization"] = "Bearer " + authToken;
    const res = await fetch(API + path, { ...opts, headers });
    if(res.status === 401){ logout(); throw new Error("unauthorized"); }
    const data = await res.json().catch(() => ({}));
    if(!res.ok) throw new Error(data.error || "server-error");
    return data;
  }

  function fmtDate(iso){
    if(!iso) return "—";
    try{ return new Date(iso).toLocaleDateString("ar-EG", { year:"numeric", month:"short", day:"numeric" }); }
    catch(e){ return iso; }
  }
  function fmtDateTime(iso){
    if(!iso) return "لسه ماتفحصش";
    try{ return new Date(iso).toLocaleString("ar-EG", { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" }); }
    catch(e){ return iso; }
  }

  /* ===================== تسجيل الدخول ===================== */
  function showLogin(){
    $("loginScreen").style.display = "flex";
    $("dashScreen").style.display = "none";
  }
  function showDash(){
    $("loginScreen").style.display = "none";
    $("dashScreen").style.display = "block";
    loadOverview();
  }
  function logout(){
    authToken = "";
    localStorage.removeItem("admin_token");
    showLogin();
  }
  $("btnLogout").addEventListener("click", logout);

  $("btnLogin").addEventListener("click", async () => {
    const username = $("inUsername").value.trim();
    const password = $("inPassword").value;
    const err = $("loginError");
    err.textContent = "";
    if(!username || !password){ err.textContent = "من فضلك املأ اسم المستخدم وكلمة السر"; return; }
    try{
      const data = await api("/api/admin/login", { method: "POST", body: JSON.stringify({ username, password }) });
      authToken = data.token;
      localStorage.setItem("admin_token", authToken);
      showDash();
    }catch(e){
      err.textContent = "بيانات الدخول غلط";
    }
  });
  $("inPassword").addEventListener("keydown", (e) => { if(e.key === "Enter") $("btnLogin").click(); });

  /* ===================== التبويبات ===================== */
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      $("page-" + btn.dataset.tab).classList.add("active");
      if(btn.dataset.tab === "licenses") loadLicenses();
      if(btn.dataset.tab === "versions") loadVersions();
      if(btn.dataset.tab === "devices") loadDevices();
    });
  });

  /* ===================== نظرة عامة ===================== */
  async function loadOverview(){
    try{
      const stats = await api("/api/admin/stats");
      $("statsGrid").innerHTML = `
        <div class="stat-card"><div class="num">${stats.total}</div><div class="lbl">إجمالي التراخيص</div></div>
        <div class="stat-card ok"><div class="num">${stats.active}</div><div class="lbl">نشطة</div></div>
        <div class="stat-card warn"><div class="num">${stats.expiringSoon}</div><div class="lbl">هتنتهي قريب (٥ أيام)</div></div>
        <div class="stat-card bad"><div class="num">${stats.expired}</div><div class="lbl">منتهية</div></div>
        <div class="stat-card bad"><div class="num">${stats.revoked}</div><div class="lbl">ملغاة</div></div>`;
    }catch(e){ showToast("تعذّر تحميل الإحصائيات"); }
  }

  /* ===================== فورم إصدار ترخيص (مستخدم مرتين: نظرة عامة + تاب التراخيص) ===================== */
  function durationGridHtml(prefix){
    const options = [
      ["day","يوم"], ["3days","3 أيام"], ["week","أسبوع"], ["month","شهر"],
      ["3months","3 شهور"], ["6months","6 شهور"], ["year","سنة"], ["custom","تاريخ محدد"]
    ];
    return `<div class="dur-grid" id="${prefix}DurGrid">` +
      options.map((o,i) => `<button type="button" class="dur-btn${i===3?' active':''}" data-dur="${o[0]}">${o[1]}</button>`).join("") +
      `</div><input type="date" id="${prefix}CustomDate" style="display:none; margin-bottom:10px;">`;
  }
  function licenseFormHtml(prefix){
    return `
      <div class="row-2">
        <div class="field"><label>اسم العميل *</label><input type="text" id="${prefix}Customer" placeholder="مثال: محمد الشرقاوي"></div>
        <div class="field"><label>اسم المحل / الفرع *</label><input type="text" id="${prefix}Store" placeholder="مثال: فرع المعادي"></div>
      </div>
      <div class="row-2">
        <div class="field"><label>رقم الهاتف (اختياري)</label><input type="tel" id="${prefix}Phone"></div>
        <div class="field"><label>ملاحظات (اختياري)</label><input type="text" id="${prefix}Note"></div>
      </div>
      <div class="field"><label>مدة الترخيص</label>${durationGridHtml(prefix)}</div>
      <button class="btn btn-primary" id="${prefix}BtnGenerate">🔑 إنشاء الترخيص</button>
      <div class="err" id="${prefix}Error"></div>
      <textarea class="result-key" id="${prefix}ResultKey" rows="4" readonly style="display:none;"></textarea>
      <button class="btn btn-ghost btn-sm" id="${prefix}BtnCopy" style="display:none;">📋 نسخ المفتاح</button>
    `;
  }
  function wireLicenseForm(prefix){
    let selectedDuration = "month";
    const grid = $(prefix + "DurGrid");
    grid.addEventListener("click", (e) => {
      const btn = e.target.closest(".dur-btn");
      if(!btn) return;
      grid.querySelectorAll(".dur-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      selectedDuration = btn.dataset.dur;
      $(prefix + "CustomDate").style.display = selectedDuration === "custom" ? "block" : "none";
    });
    $(prefix + "BtnGenerate").addEventListener("click", async () => {
      const customerName = $(prefix + "Customer").value.trim();
      const storeName = $(prefix + "Store").value.trim();
      const err = $(prefix + "Error");
      err.textContent = "";
      if(!customerName || !storeName){ err.textContent = "من فضلك اكتبي اسم العميل والمحل"; return; }
      try{
        const data = await api("/api/admin/licenses", {
          method: "POST",
          body: JSON.stringify({
            customerName, storeName,
            phone: $(prefix + "Phone").value.trim(),
            note: $(prefix + "Note").value.trim(),
            duration: selectedDuration,
            customDate: $(prefix + "CustomDate").value
          })
        });
        $(prefix + "ResultKey").style.display = "block";
        $(prefix + "ResultKey").value = data.token;
        $(prefix + "BtnCopy").style.display = "inline-flex";
        showToast("تم إنشاء الترخيص بنجاح");
        loadOverview();
      }catch(e){ err.textContent = "حصل خطأ أثناء الإنشاء"; }
    });
    $(prefix + "BtnCopy").addEventListener("click", () => {
      navigator.clipboard.writeText($(prefix + "ResultKey").value).then(() => showToast("تم نسخ المفتاح"));
    });
  }

  $("quickLicenseForm").innerHTML = licenseFormHtml("q");
  wireLicenseForm("q");
  $("licenseFormFull").innerHTML = licenseFormHtml("f");
  wireLicenseForm("f");

  /* ===================== قائمة التراخيص ===================== */
  async function loadLicenses(filter){
    const body = $("licensesBody");
    try{
      const data = await api("/api/admin/licenses" + (filter ? "?q=" + encodeURIComponent(filter) : ""));
      body.innerHTML = "";
      if(data.licenses.length === 0){
        body.innerHTML = '<tr class="empty-row"><td colspan="6">مفيش تراخيص لسه</td></tr>';
        return;
      }
      const now = new Date();
      data.licenses.forEach(lic => {
        const expired = new Date(lic.expires_at) < now;
        const status = lic.status === "revoked" ? "bad" : (expired ? "bad" : "ok");
        const statusText = lic.status === "revoked" ? "ملغى" : (expired ? "منتهي" : "نشط");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${lic.customer_name}</td>
          <td>${lic.store_name}</td>
          <td>${fmtDate(lic.expires_at)}</td>
          <td>${fmtDateTime(lic.last_check_at)}</td>
          <td><span class="status-pill ${status}">${statusText}</span></td>
          <td>
            <div class="row-actions">
              <button class="btn btn-ghost btn-sm" data-copy="${lic.id}">📋</button>
              ${lic.status === "revoked"
                ? `<button class="btn btn-ghost btn-sm" data-restore="${lic.id}">استرجاع</button>`
                : `<button class="btn btn-danger" data-revoke="${lic.id}">إلغاء</button>`}
              <button class="btn btn-danger" data-del="${lic.id}">حذف</button>
            </div>
          </td>`;
        tr.dataset.token = lic.token;
        body.appendChild(tr);
      });
    }catch(e){ showToast("تعذّر تحميل التراخيص"); }
  }
  $("licenseSearch").addEventListener("input", (e) => loadLicenses(e.target.value));
  $("btnRefreshLicenses").addEventListener("click", () => loadLicenses($("licenseSearch").value));

  $("licensesBody").addEventListener("click", async (e) => {
    const copyBtn = e.target.closest("[data-copy]");
    const revokeBtn = e.target.closest("[data-revoke]");
    const restoreBtn = e.target.closest("[data-restore]");
    const delBtn = e.target.closest("[data-del]");
    if(copyBtn){
      const token = copyBtn.closest("tr").dataset.token;
      navigator.clipboard.writeText(token).then(() => showToast("تم نسخ المفتاح"));
    }
    if(revokeBtn){
      if(!confirm("هيتوقف الترخيص ده عن الشغل فورًا في أي جهاز متصل بالإنترنت. تأكيد؟")) return;
      try{ await api(`/api/admin/licenses/${revokeBtn.dataset.revoke}/revoke`, { method: "POST" }); showToast("تم إلغاء الترخيص"); loadLicenses($("licenseSearch").value); loadOverview(); }
      catch(e){ showToast("حصل خطأ"); }
    }
    if(restoreBtn){
      try{ await api(`/api/admin/licenses/${restoreBtn.dataset.restore}/restore`, { method: "POST" }); showToast("تم استرجاع الترخيص"); loadLicenses($("licenseSearch").value); loadOverview(); }
      catch(e){ showToast("حصل خطأ"); }
    }
    if(delBtn){
      if(!confirm("حذف نهائي للترخيص من السجل. متأكدة؟")) return;
      try{ await api(`/api/admin/licenses/${delBtn.dataset.del}`, { method: "DELETE" }); showToast("تم الحذف"); loadLicenses($("licenseSearch").value); loadOverview(); }
      catch(e){ showToast("حصل خطأ"); }
    }
  });

  /* ===================== التحديثات ===================== */
  $("uploadForm").innerHTML = `
    <div class="row-2">
      <div class="field"><label>المنصة</label>
        <select id="uPlatform"><option value="win">ويندوز (exe)</option><option value="android">أندرويد (apk)</option></select>
      </div>
      <div class="field"><label>رقم النسخة</label><input type="text" id="uVersion" placeholder="مثال: 1.0.1"></div>
    </div>
    <div class="field"><label>ملاحظات النسخة (اختياري)</label><input type="text" id="uNotes" placeholder="إيه الجديد في النسخة دي؟"></div>
    <div class="field">
      <label>الملف</label>
      <div class="file-drop" id="fileDropZone">دوسي هنا لاختيار ملف exe أو apk</div>
      <input type="file" id="uFile" accept=".exe,.apk" style="display:none;">
    </div>
    <div class="progress-bar-wrap" id="uProgressWrap"><div class="progress-bar" id="uProgressBar"></div></div>
    <button class="btn btn-primary" id="btnUpload" style="margin-top:12px;">⬆️ رفع ونشر</button>
    <div class="err" id="uploadError"></div>
  `;
  let selectedFile = null;
  $("fileDropZone").addEventListener("click", () => $("uFile").click());
  $("uFile").addEventListener("change", (e) => {
    selectedFile = e.target.files[0] || null;
    $("fileDropZone").textContent = selectedFile ? ("الملف المختار: " + selectedFile.name) : "دوسي هنا لاختيار ملف exe أو apk";
  });
  $("btnUpload").addEventListener("click", () => {
    const platform = $("uPlatform").value;
    const version = $("uVersion").value.trim();
    const err = $("uploadError");
    err.textContent = "";
    if(!selectedFile){ err.textContent = "من فضلك اختاري ملف"; return; }
    if(!version){ err.textContent = "من فضلك اكتبي رقم النسخة"; return; }

    const form = new FormData();
    form.append("file", selectedFile);
    form.append("platform", platform);
    form.append("version", version);
    form.append("notes", $("uNotes").value.trim());

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/admin/versions/upload");
    xhr.setRequestHeader("Authorization", "Bearer " + authToken);
    $("uProgressWrap").style.display = "block";
    xhr.upload.onprogress = (e) => {
      if(e.lengthComputable) $("uProgressBar").style.width = Math.round((e.loaded / e.total) * 100) + "%";
    };
    xhr.onload = () => {
      $("uProgressWrap").style.display = "none";
      $("uProgressBar").style.width = "0%";
      if(xhr.status >= 200 && xhr.status < 300){
        showToast("تم رفع النسخة ونشرها");
        selectedFile = null;
        $("uFile").value = "";
        $("fileDropZone").textContent = "دوسي هنا لاختيار ملف exe أو apk";
        loadVersions();
      } else {
        err.textContent = "حصل خطأ أثناء الرفع (الملف كبير أوي أو مشكلة في الاتصال)";
      }
    };
    xhr.onerror = () => { $("uProgressWrap").style.display = "none"; err.textContent = "تعذّر الاتصال بالسيرفر"; };
    xhr.send(form);
  });

  async function loadVersions(){
    const body = $("versionsBody");
    try{
      const data = await api("/api/admin/versions");
      body.innerHTML = "";
      if(data.versions.length === 0){
        body.innerHTML = '<tr class="empty-row"><td colspan="4">لسه مفيش نسخ منشورة</td></tr>';
        return;
      }
      data.versions.forEach(v => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${v.platform === "win" ? "ويندوز" : "أندرويد"}</td>
          <td>${v.version}</td>
          <td>${fmtDateTime(v.published_at)}</td>
          <td><span class="status-pill ${v.is_active ? "ok" : "bad"}">${v.is_active ? "الحالية" : "قديمة"}</span></td>`;
        body.appendChild(tr);
      });
    }catch(e){ showToast("تعذّر تحميل النسخ"); }
  }

  /* ===================== الأجهزة والإعدادات عن بُعد ===================== */
  async function loadDevices(){
    const body = $("devicesBody");
    try{
      const data = await api("/api/admin/devices");
      body.innerHTML = "";
      if(data.devices.length === 0){
        body.innerHTML = '<tr class="empty-row"><td colspan="4">لسه مفيش أجهزة اتصلت بالسيرفر</td></tr>';
        return;
      }
      data.devices.forEach(d => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${d.customer_name}<br><span style="color:var(--ink-dim); font-size:11px;">${d.store_name}</span></td>
          <td style="font-family:var(--font-num); font-size:11px;">${d.device_id}</td>
          <td>${fmtDateTime(d.last_seen)}</td>
          <td>
            <div class="row-actions">
              <button class="btn btn-ghost btn-sm" data-cfg-device="${d.device_id}">⚙️ الجهاز ده بس</button>
              <button class="btn btn-ghost btn-sm" data-cfg-license="${d.license_id}" data-lic-name="${d.customer_name} — ${d.store_name}">⚙️ كل أجهزة الترخيص</button>
            </div>
          </td>`;
        body.appendChild(tr);
      });
    }catch(e){ showToast("تعذّر تحميل الأجهزة"); }
  }
  $("devicesBody").addEventListener("click", (e) => {
    const devBtn = e.target.closest("[data-cfg-device]");
    const licBtn = e.target.closest("[data-cfg-license]");
    if(devBtn) openConfigModal("device", devBtn.dataset.cfgDevice, "الجهاز: " + devBtn.dataset.cfgDevice);
    if(licBtn) openConfigModal("license", licBtn.dataset.cfgLicense, "كل أجهزة: " + licBtn.dataset.licName);
  });

  /* ===================== مودال ضبط الإعدادات عن بُعد ===================== */
  let configScope = { type: null, key: null };
  let configFileData = null;

  async function openConfigModal(scopeType, scopeKey, label){
    configScope = { type: scopeType, key: scopeKey };
    configFileData = null;
    $("configFile").value = "";
    $("configFileDropZone").textContent = "دوسي هنا لاختيار ملف JSON";
    $("configModalError").textContent = "";
    $("configModalTitle").textContent = scopeType === "device" ? "إعدادات جهاز واحد" : "إعدادات كل أجهزة الترخيص";
    $("configModalSub").textContent = label;
    $("configModalStatus").textContent = "جاري التحميل...";
    $("configModalOverlay").style.display = "flex";
    try{
      const data = await api(`/api/admin/config/${scopeType}/${encodeURIComponent(scopeKey)}`);
      $("configModalStatus").textContent = data.hasConfig
        ? `✅ مخصّص حاليًا — آخر تحديث: ${fmtDateTime(data.updatedAt)}`
        : "مفيش تخصيص حاليًا — شغّال بإعداداته المحلية العادية";
    }catch(e){ $("configModalStatus").textContent = ""; }
  }
  $("btnCloseConfigModal").addEventListener("click", () => { $("configModalOverlay").style.display = "none"; });

  $("configFileDropZone").addEventListener("click", () => $("configFile").click());
  $("configFile").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try{
        const parsed = JSON.parse(ev.target.result);
        if(!parsed.settings && !parsed.products){ throw new Error("bad-shape"); }
        configFileData = parsed;
        $("configFileDropZone").textContent = "✅ الملف المختار: " + file.name;
      }catch(err){
        configFileData = null;
        $("configModalError").textContent = "الملف ده مش نسخة احتياطية صالحة";
      }
    };
    reader.readAsText(file);
  });

  $("btnApplyConfig").addEventListener("click", async () => {
    const err = $("configModalError");
    err.textContent = "";
    if(!configFileData){ err.textContent = "من فضلك اختاري ملف نسخة احتياطية صالح أولًا"; return; }
    try{
      await api(`/api/admin/config/${configScope.type}/${encodeURIComponent(configScope.key)}`, {
        method: "PUT",
        body: JSON.stringify({ settings: configFileData.settings || null, products: configFileData.products || null })
      });
      showToast("تم تطبيق الإعدادات — هتوصل للجهاز/الأجهزة في أقرب مزامنة");
      $("configModalOverlay").style.display = "none";
    }catch(e){ err.textContent = "حصل خطأ أثناء الحفظ"; }
  });

  $("btnClearConfig").addEventListener("click", async () => {
    if(!confirm("هيرجع الجهاز/الأجهزة يشتغلوا بإعداداتهم المحلية العادية بدل التخصيص ده. تأكيد؟")) return;
    try{
      await api(`/api/admin/config/${configScope.type}/${encodeURIComponent(configScope.key)}`, { method: "DELETE" });
      showToast("تم إلغاء التخصيص");
      $("configModalOverlay").style.display = "none";
    }catch(e){ showToast("حصل خطأ"); }
  });

  /* ===================== بدء التشغيل ===================== */
  if(authToken) showDash(); else showLogin();
})();
