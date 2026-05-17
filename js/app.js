// ============ 密码管理器 - 核心逻辑 ============

// 数据结构：{ id, site, account, password }
var entries = [];

// ---- 主密码锁 ----
var failCount = 0;
var lockUntil = 0;

// 纯 JavaScript SHA-256 实现（crypto.subtle 不可用时的回退方案）
function sha256Pure(message) {
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

  var l = message.length * 8;
  var padLen = 64 - ((message.length + 9) % 64);
  if (padLen === 64) padLen = 0;
  var paddedLen = message.length + 1 + padLen + 8;
  var padded = new Uint8Array(paddedLen);
  padded.set(message);
  padded[message.length] = 0x80;
  padded[paddedLen - 2] = (l >>> 8) & 0xff;
  padded[paddedLen - 1] = l & 0xff;

  var W = new Uint32Array(64);
  for (var offset = 0; offset < paddedLen; offset += 64) {
    for (var t = 0; t < 16; t++) {
      var i = offset + t * 4;
      W[t] = (padded[i] << 24) | (padded[i+1] << 16) | (padded[i+2] << 8) | padded[i+3];
    }
    for (var t = 16; t < 64; t++) {
      var s0 = ((W[t-15] >>> 7) | (W[t-15] << 25)) ^ ((W[t-15] >>> 18) | (W[t-15] << 14)) ^ (W[t-15] >>> 3);
      var s1 = ((W[t-2] >>> 17) | (W[t-2] << 15)) ^ ((W[t-2] >>> 19) | (W[t-2] << 13)) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }

    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (var t = 0; t < 64; t++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  var hex = '';
  for (var i = 0; i < 8; i++) { hex += (H[i] >>> 0).toString(16).padStart(8, '0'); }
  return hex;
}

function hashPw(pw) {
  var encoder = new TextEncoder();
  var data = encoder.encode(pw);
  if (crypto.subtle) {
    return crypto.subtle.digest('SHA-256', data).then(function (hashBuffer) {
      var hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    });
  }
  // crypto.subtle 不可用时的纯 JS 回退（如手机 HTTP 访问）
  return Promise.resolve(sha256Pure(data));
}

function hasMasterPw() {
  return localStorage.getItem('pw_master_hash') !== null;
}

function getMasterHash() {
  return localStorage.getItem('pw_master_hash');
}

function setMasterHash(hash) {
  localStorage.setItem('pw_master_hash', hash);
}

function isLockedOut() {
  return Date.now() < lockUntil;
}

function secondsLeft() {
  return Math.ceil((lockUntil - Date.now()) / 1000);
}

function initLock() {
  var overlay = document.getElementById('lockOverlay');
  var title   = document.getElementById('lockTitle');
  var desc    = document.getElementById('lockDesc');
  var input1  = document.getElementById('lockInput1');
  var input2  = document.getElementById('lockInput2');
  var btn     = document.getElementById('lockBtn');
  var error   = document.getElementById('lockError');
  var timerEl = document.getElementById('lockTimer');

  overlay.style.display = 'flex';
  document.getElementById('changePwBtn').style.display = 'none';

  if (hasMasterPw()) {
    // 已有主密码 → 解锁模式
    title.textContent = '🔐 密码管理器';
    desc.textContent = '请输入主密码解锁';
    input1.style.display = '';
    input2.style.display = 'none';
    input1.value = '';
    input1.placeholder = '主密码';
    error.textContent = '';
    timerEl.textContent = '';
    btn.textContent = '解锁';
    btn.onclick = doUnlock;
    input1.onkeydown = function (e) { if (e.key === 'Enter') doUnlock(); };

    if (isLockedOut()) {
      input1.disabled = true;
      btn.disabled = true;
      startLockTimer();
    }
  } else {
    // 首次使用 → 设置模式
    title.textContent = '🔐 首次使用';
    desc.textContent = '请设置一个主密码（至少 4 位）';
    input1.style.display = '';
    input1.placeholder = '设置主密码';
    input2.style.display = '';
    input2.value = '';
    input2.placeholder = '确认主密码';
    error.textContent = '';
    timerEl.textContent = '';
    btn.textContent = '设置';
    btn.onclick = doSetup;
    input2.onkeydown = function (e) { if (e.key === 'Enter') doSetup(); };
    input1.onkeydown = function () {};
  }
}

function startLockTimer() {
  var timerEl = document.getElementById('lockTimer');
  var input1  = document.getElementById('lockInput1');
  var btn     = document.getElementById('lockBtn');
  var error   = document.getElementById('lockError');

  function tick() {
    if (!isLockedOut()) {
      input1.disabled = false;
      btn.disabled = false;
      timerEl.textContent = '';
      error.textContent = '';
      failCount = 0;
      return;
    }
    timerEl.textContent = '请等待 ' + secondsLeft() + ' 秒后重试';
    error.textContent = '连续 3 次错误，已锁定 30 秒';
    setTimeout(tick, 200);
  }
  tick();
}

async function doUnlock() {
  var input1 = document.getElementById('lockInput1');
  var error  = document.getElementById('lockError');
  var pw = input1.value;
  if (!pw) { error.textContent = '请输入主密码'; return; }

  try {
    var hash = await hashPw(pw);
    if (hash === getMasterHash()) {
      failCount = 0;
      lockUntil = 0;
      unlock();
    } else {
      failCount++;
      input1.value = '';
      if (failCount >= 3) {
        lockUntil = Date.now() + 30000;
        document.getElementById('lockInput1').disabled = true;
        document.getElementById('lockBtn').disabled = true;
        startLockTimer();
        error.textContent = '连续 3 次错误，已锁定 30 秒';
      } else {
        error.textContent = '密码错误（剩余 ' + (3 - failCount) + ' 次机会）';
      }
    }
  } catch (e) {
    error.textContent = '加密失败：' + e.message;
  }
}

async function doSetup() {
  var input1 = document.getElementById('lockInput1');
  var input2 = document.getElementById('lockInput2');
  var error  = document.getElementById('lockError');
  var pw1 = input1.value;
  var pw2 = input2.value;

  if (!pw1) { error.textContent = '请输入主密码'; return; }
  if (pw1.length < 4) { error.textContent = '主密码至少需要 4 位'; return; }
  if (pw1 !== pw2) { error.textContent = '两次输入不一致'; return; }

  try {
    var hash = await hashPw(pw1);
    setMasterHash(hash);
    input1.value = '';
    input2.value = '';
    unlock();
  } catch (e) {
    error.textContent = '加密失败：' + e.message;
  }
}

function unlock() {
  document.getElementById('lockOverlay').style.display = 'none';
  document.getElementById('changePwBtn').style.display = '';
}

function lock() {
  document.getElementById('lockOverlay').style.display = 'flex';
  document.getElementById('changePwBtn').style.display = 'none';
  failCount = 0;
  initLock();
}

// ---- 修改主密码 ----
function showChangePwModal() {
  document.getElementById('changePwModal').style.display = 'flex';
  document.getElementById('oldPw').value = '';
  document.getElementById('newPw1').value = '';
  document.getElementById('newPw2').value = '';
  document.getElementById('changePwError').textContent = '';
}

function hideChangePwModal() {
  document.getElementById('changePwModal').style.display = 'none';
}

async function handleChangePw() {
  var oldPw  = document.getElementById('oldPw').value;
  var newPw1 = document.getElementById('newPw1').value;
  var newPw2 = document.getElementById('newPw2').value;
  var error  = document.getElementById('changePwError');

  if (!oldPw) { error.textContent = '请输入原主密码'; return; }
  var oldHash = await hashPw(oldPw);
  if (oldHash !== getMasterHash()) { error.textContent = '原密码错误'; return; }
  if (!newPw1) { error.textContent = '请输入新密码'; return; }
  if (newPw1.length < 4) { error.textContent = '新密码至少需要 4 位'; return; }
  if (newPw1 !== newPw2) { error.textContent = '两次输入不一致'; return; }

  var newHash = await hashPw(newPw1);
  setMasterHash(newHash);
  hideChangePwModal();
  showToast('主密码已更新');
}

// ---- 持久化 ----
function isServerMode() {
  return window.location.protocol === 'http:' || window.location.protocol === 'https:';
}

function load(callback) {
  if (isServerMode()) {
    fetch('/api/data')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        entries = data || [];
        if (callback) callback();
      })
      .catch(function () {
        // 服务器不可用时退回 localStorage
        var raw = localStorage.getItem('pw_manager_data');
        if (raw) entries = JSON.parse(raw);
        if (callback) callback();
      });
  } else {
    try {
      var raw = localStorage.getItem('pw_manager_data');
      if (raw) entries = JSON.parse(raw);
    } catch (e) {
      entries = [];
    }
    if (callback) callback();
  }
}

function save() {
  var json = JSON.stringify(entries);
  localStorage.setItem('pw_manager_data', json);
  if (isServerMode()) {
    fetch('/api/data', { method: 'POST', body: json }).catch(function () {});
  }
}

// ---- TXT 解析 ----

/**
 * 解析一行文本，自动识别分隔符
 * 支持格式：
 *   网站,账号,密码  /  账号,密码
 *   网站：账号：密码  /  账号：密码
 *   网站 账号 密码    /  账号 密码
 *   制表符分隔
 */
function parseLine(line) {
  line = line.trim();
  if (!line) return null;

  var parts;

  // 逗号分隔（半角/全角）
  if (line.includes(',')) {
    parts = line.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  } else if (line.includes('，')) {
    parts = line.split('，').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  }
  // 全角/半角冒号
  else if (line.includes('：') || line.includes(':')) {
    parts = line.split(/[：:]/).map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  }
  // Tab 分隔
  else if (line.includes('\t')) {
    parts = line.split('\t').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  }
  // 空格分隔
  else {
    parts = line.split(/\s+/).filter(function (s) { return s; });
  }

  if (!parts || parts.length < 2) return null;

  if (parts.length >= 3) {
    // 网站 ... 密码（中间部分合并为账号）
    return {
      site: parts[0],
      account: parts.slice(0, -1).join(' '),
      password: parts[parts.length - 1]
    };
  }
  // 只有两列 → 账号,密码
  return { site: '', account: parts[0], password: parts[1] };
}

function handleFile(file) {
  var reader = new FileReader();
  reader.onload = function (e) {
    var lines = e.target.result.split(/\r?\n/);
    var added = 0;
    lines.forEach(function (line) {
      var parsed = parseLine(line);
      if (parsed) {
        entries.push({
          id: Date.now() + Math.random(),
          site: parsed.site,
          account: parsed.account,
          password: parsed.password
        });
        added++;
      }
    });
    save();
    render();
    alert('成功导入 ' + added + ' 条记录');
  };
  reader.readAsText(file);
}

// ---- 渲染 ----

function render() {
  var list = document.getElementById('cardList');
  var header = document.getElementById('cardListHeader');
  var searchTerm = document.getElementById('searchInput').value.toLowerCase();

  var filtered = entries;
  if (searchTerm) {
    filtered = entries.filter(function (e) {
      return e.site.toLowerCase().includes(searchTerm) ||
             e.account.toLowerCase().includes(searchTerm) ||
             e.password.toLowerCase().includes(searchTerm);
    });
  }

  // 全选栏
  if (entries.length > 0) {
    header.style.display = 'flex';
  } else {
    header.style.display = 'none';
  }

  if (filtered.length === 0) {
    list.innerHTML =
      '<div class="empty-state">' +
        '<div class="empty-icon">📭</div>' +
        '<p>' + (entries.length === 0 ? '还没有密码记录' : '没有匹配的记录') + '</p>' +
      '</div>';
  } else {
    list.innerHTML = filtered.map(function (e) {
      var realIdx = entries.indexOf(e);
      var sel = selectedSet[e.id] ? ' checked' : '';
      var firstChar = (e.site || '?').charAt(0).toUpperCase();
      var isMasked = true; // 默认掩码，用 innerHTML 渲染后由 togglePw 控制

      return '<div class="pw-card">' +
        '<input type="checkbox" class="card-checkbox" onchange="toggleSelect(' + e.id + ',this.checked)"' + sel + '>' +
        '<div class="card-body">' +
          '<div class="card-site">' +
            '<div class="card-site-icon">' + esc(firstChar) + '</div>' +
            '<span>' + esc(e.site || '（无网站）') + '</span>' +
          '</div>' +
          '<div class="card-meta">' +
            '<span>👤 ' + esc(e.account) + '</span>' +
            '<span>🔑 <span class="card-password" id="pw-' + realIdx + '">' + '•'.repeat(10) + '</span>' +
            '<span id="pw-text-' + realIdx + '" style="display:none;font-family:monospace;">' + esc(e.password) + '</span></span>' +
          '</div>' +
        '</div>' +
        '<div class="card-actions">' +
          '<button class="btn-sm" onclick="showEditModal(' + realIdx + ')">✏️</button>' +
          '<button class="btn-sm" onclick="togglePw(' + realIdx + ')" id="btn-toggle-' + realIdx + '">👁</button>' +
          '<button class="btn-sm" onclick="copyText(\'' + escJs(e.account) + '\')">📋 号</button>' +
          '<button class="btn-sm" onclick="copyText(\'' + escJs(e.password) + '\')">📋 密</button>' +
          '<button class="btn-sm" style="color:var(--danger);" onclick="delEntry(' + realIdx + ')">✕</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  document.getElementById('stats').textContent =
    '共 ' + entries.length + ' 条记录' +
    (searchTerm && filtered.length !== entries.length ? '（筛选显示 ' + filtered.length + ' 条）' : '');
}

// ---- 工具函数 ----

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function escJs(s) {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function togglePw(idx) {
  var masked = document.getElementById('pw-' + idx);
  var text   = document.getElementById('pw-text-' + idx);
  var btn    = document.getElementById('btn-toggle-' + idx);
  if (masked.style.display === 'none') {
    masked.style.display = '';
    text.style.display = 'none';
    btn.textContent = '👁';
  } else {
    masked.style.display = 'none';
    text.style.display = '';
    btn.textContent = '🙈';
  }
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(function () {
    showToast('已复制');
  }).catch(function () {
    showToast('复制失败');
  });
}

function showToast(msg) {
  var toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);
  // 触发动画
  requestAnimationFrame(function () {
    toast.classList.add('toast-show');
  });
  setTimeout(function () {
    toast.classList.remove('toast-show');
    setTimeout(function () { document.body.removeChild(toast); }, 300);
  }, 1200);
}

function delEntry(idx) {
  if (!confirm('确定删除这条记录？')) return;
  entries.splice(idx, 1);
  save();
  render();
}

// ---- 编辑功能 ----
var editingIdx = -1;

function showEditModal(idx) {
  editingIdx = idx;
  var e = entries[idx];
  document.getElementById('editSite').value = e.site || '';
  document.getElementById('editAccount').value = e.account;
  document.getElementById('editPassword').value = e.password;
  document.getElementById('editError').textContent = '';
  document.getElementById('editModal').style.display = 'flex';
}

function hideEditModal() {
  document.getElementById('editModal').style.display = 'none';
  editingIdx = -1;
}

function handleEdit() {
  var site = document.getElementById('editSite').value.trim();
  var account = document.getElementById('editAccount').value.trim();
  var password = document.getElementById('editPassword').value.trim();
  var error = document.getElementById('editError');

  if (!account || !password) { error.textContent = '账号和密码不能为空'; return; }

  entries[editingIdx].site = site;
  entries[editingIdx].account = account;
  entries[editingIdx].password = password;
  save();
  render();
  hideEditModal();
  showToast('已保存');
}

// 编辑弹窗里的密码生成
function genEditPassword() {
  document.getElementById('editPassword').value = generatePassword();
}

// ---- 多选功能 ----
var selectedSet = {};

function getSelectedIds() {
  var ids = [];
  for (var id in selectedSet) {
    if (selectedSet[id]) ids.push(parseFloat(id));
  }
  return ids;
}

function toggleSelect(id, checked) {
  if (checked) {
    selectedSet[id] = true;
  } else {
    delete selectedSet[id];
    document.getElementById('selectAll').checked = false;
  }
  updateBatchBar();
}

function selectAllToggle(checked) {
  selectedSet = {};
  if (checked) {
    entries.forEach(function (e) { selectedSet[e.id] = true; });
  }
  render();
  updateBatchBar();
}

function updateBatchBar() {
  var ids = getSelectedIds();
  var bar = document.getElementById('batchBar');
  if (ids.length > 0) {
    bar.style.display = 'flex';
    document.getElementById('batchCount').textContent = '已选 ' + ids.length + ' 条';
  } else {
    bar.style.display = 'none';
  }
}

function batchDelete() {
  var ids = getSelectedIds();
  if (ids.length === 0) return;
  if (!confirm('确定删除选中的 ' + ids.length + ' 条记录？')) return;
  var idSet = {};
  ids.forEach(function (id) { idSet[id] = true; });
  entries = entries.filter(function (e) { return !idSet[e.id]; });
  selectedSet = {};
  save();
  render();
  updateBatchBar();
}

// ---- AES 加解密 ----
function uint8ToBase64(arr) {
  var binary = '';
  var len = arr.length;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

function base64ToUint8(str) {
  var binary = atob(str);
  var len = binary.length;
  var arr = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}

async function encryptData(plaintext, password) {
  var enc = new TextEncoder();
  var salt = crypto.getRandomValues(new Uint8Array(16));

  var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  var key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  var iv = crypto.getRandomValues(new Uint8Array(12));
  var encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(plaintext)
  );

  var combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return uint8ToBase64(combined);
}

async function decryptData(b64data, password) {
  var combined = base64ToUint8(b64data);
  var salt = combined.slice(0, 16);
  var iv = combined.slice(16, 28);
  var ciphertext = combined.slice(28);

  var enc = new TextEncoder();
  var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  var key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  var decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// ---- 导出/导入流程 ----
var cryptoAction = ''; // 'export' | 'import'
var pendingEncFile = null;

function showCryptoModal(action) {
  cryptoAction = action;
  var title = document.getElementById('cryptoPwTitle');
  var desc = document.getElementById('cryptoPwDesc');
  var input1 = document.getElementById('cryptoPw1');
  var input2 = document.getElementById('cryptoPw2');
  var error = document.getElementById('cryptoPwError');
  var btn = document.getElementById('cryptoPwConfirm');

  input1.value = '';
  input2.value = '';
  error.textContent = '';

  if (action === 'export') {
    title.textContent = '导出备份';
    desc.textContent = '请设置一个加密口令来保护备份文件';
    input1.placeholder = '设置加密口令';
    input2.style.display = '';
    input2.placeholder = '确认口令';
    btn.textContent = '导出';
    input2.onkeydown = function (e) { if (e.key === 'Enter') handleCryptoConfirm(); };
    input1.onkeydown = function () {};
  } else {
    title.textContent = '导入备份';
    desc.textContent = '请输入备份文件的加密口令';
    input1.placeholder = '加密口令';
    input2.style.display = 'none';
    btn.textContent = '导入';
    input1.onkeydown = function (e) { if (e.key === 'Enter') handleCryptoConfirm(); };
  }

  document.getElementById('cryptoPwModal').style.display = 'flex';
}

function hideCryptoModal() {
  document.getElementById('cryptoPwModal').style.display = 'none';
  cryptoAction = '';
  pendingEncFile = null;
}

async function handleCryptoConfirm() {
  var pw1 = document.getElementById('cryptoPw1').value;
  var pw2 = document.getElementById('cryptoPw2').value;
  var error = document.getElementById('cryptoPwError');

  if (!pw1) { error.textContent = '请输入口令'; return; }

  if (cryptoAction === 'export') {
    if (pw1.length < 4) { error.textContent = '口令至少需要 4 位'; return; }
    if (pw1 !== pw2) { error.textContent = '两次输入不一致'; return; }
    try {
      var json = JSON.stringify(entries);
      var encrypted = await encryptData(json, pw1);
      triggerDownload(encrypted);
      hideCryptoModal();
      showToast('备份已导出');
    } catch (e) {
      error.textContent = '加密失败：' + e.message;
    }
  } else {
    if (!pendingEncFile) { error.textContent = '请先选择 .enc 文件'; return; }
    try {
      var text = await readFileAsText(pendingEncFile);
      var decrypted = await decryptData(text, pw1);
      var imported = JSON.parse(decrypted);
      var merged = mergeEntries(imported);
      save();
      render();
      hideCryptoModal();
      showToast('成功导入 ' + merged.added + ' 条，跳过 ' + merged.skipped + ' 条重复');
    } catch (e) {
      error.textContent = '解密失败，口令错误或文件损坏';
    }
  }
}

function triggerDownload(b64data) {
  var blob = new Blob([b64data], { type: 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'passwords-backup-' + new Date().toISOString().slice(0, 10) + '.enc';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function readFileAsText(file) {
  return new Promise(function (resolve, reject) {
    var reader = new FileReader();
    reader.onload = function (e) { resolve(e.target.result); };
    reader.onerror = function () { reject(new Error('读取文件失败')); };
    reader.readAsText(file);
  });
}

function mergeEntries(imported) {
  if (!Array.isArray(imported)) throw new Error('数据格式错误');
  var added = 0;
  var skipped = 0;
  var existingKeys = {};
  entries.forEach(function (e) {
    existingKeys[e.site + '|||' + e.account + '|||' + e.password] = true;
  });
  imported.forEach(function (item) {
    if (!item.site && !item.account && !item.password) return;
    var key = (item.site || '') + '|||' + (item.account || '') + '|||' + (item.password || '');
    if (existingKeys[key]) { skipped++; return; }
    existingKeys[key] = true;
    entries.push({
      id: Date.now() + Math.random(),
      site: item.site || '',
      account: item.account || '',
      password: item.password || ''
    });
    added++;
  });
  return { added: added, skipped: skipped };
}

// ---- 随机密码生成 ----

var LOWER = 'abcdefghijklmnopqrstuvwxyz';
var UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
var DIGIT = '0123456789';
var SYMBOL = '!@#$%^&*()_+-=[]{}|;:,.<>?';

function generatePassword() {
  var length = parseInt(document.getElementById('genLength').value);
  var useUpper = document.getElementById('genUpper').checked;
  var useNumber = document.getElementById('genNumber').checked;
  var useSymbol = document.getElementById('genSymbol').checked;

  var charset = LOWER;
  if (useUpper) charset += UPPER;
  if (useNumber) charset += DIGIT;
  if (useSymbol) charset += SYMBOL;

  // 使用 crypto.getRandomValues 生成安全随机密码
  var arr = new Uint32Array(length);
  crypto.getRandomValues(arr);

  var result = '';
  for (var i = 0; i < length; i++) {
    result += charset[arr[i] % charset.length];
  }

  // 确保至少包含每种选定类型的字符
  var required = '';
  if (useUpper) required += UPPER[arr[0] % UPPER.length];
  if (useNumber) required += DIGIT[arr[1] % DIGIT.length];
  if (useSymbol) required += SYMBOL[arr[2] % SYMBOL.length];

  if (required.length > 0) {
    result = result.substring(0, Math.max(0, length - required.length)) + required;
  }

  document.getElementById('genPreview').textContent = result;
  return result;
}

function showGenPanel() {
  document.getElementById('genPanel').style.display = 'block';
  generatePassword();
}

function useGenPassword() {
  var pw = document.getElementById('genPreview').textContent;
  if (pw) document.getElementById('addPassword').value = pw;
}

// ---- 添加记录弹窗 ----
function showAddModal() {
  document.getElementById('addSite').value = '';
  document.getElementById('addAccount').value = '';
  document.getElementById('addPassword').value = '';
  document.getElementById('addError').textContent = '';
  document.getElementById('genPanel').style.display = 'none';
  document.getElementById('addModal').style.display = 'flex';
}

function hideAddModal() {
  document.getElementById('addModal').style.display = 'none';
}

document.addEventListener('DOMContentLoaded', function () {
  // 主密码锁屏初始化
  initLock();

  // 文件导入
  document.getElementById('fileInput').addEventListener('change', function () {
    if (this.files.length > 0) {
      handleFile(this.files[0]);
      this.value = '';
    }
  });

  document.getElementById('searchInput').addEventListener('input', render);

  // 添加记录
  document.getElementById('addEntryBtn').addEventListener('click', showAddModal);
  document.getElementById('addConfirm').addEventListener('click', function () {
    var site    = document.getElementById('addSite').value.trim();
    var account = document.getElementById('addAccount').value.trim();
    var password = document.getElementById('addPassword').value.trim();
    var error = document.getElementById('addError');

    if (!account || !password) {
      error.textContent = '账号和密码不能为空';
      return;
    }

    entries.push({
      id: Date.now() + Math.random(),
      site: site,
      account: account,
      password: password
    });
    save();
    render();
    hideAddModal();
    showToast('已添加');
  });
  document.getElementById('addCancel').addEventListener('click', hideAddModal);

  document.getElementById('clearBtn').addEventListener('click', function () {
    if (!confirm('确定清空所有记录？此操作不可恢复。')) return;
    entries = [];
    save();
    render();
  });

  // 密码生成器
  document.getElementById('genBtn').addEventListener('click', showGenPanel);
  document.getElementById('genRefresh').addEventListener('click', generatePassword);
  document.getElementById('genUse').addEventListener('click', function () {
    useGenPassword();
    document.getElementById('genPanel').style.display = 'none';
  });
  document.getElementById('genLength').addEventListener('input', function () {
    document.getElementById('lenVal').textContent = this.value;
    generatePassword();
  });

  // 修改主密码
  document.getElementById('changePwBtn').addEventListener('click', showChangePwModal);
  document.getElementById('changePwConfirm').addEventListener('click', handleChangePw);
  document.getElementById('changePwCancel').addEventListener('click', hideChangePwModal);

  // 编辑
  document.getElementById('editConfirm').addEventListener('click', handleEdit);
  document.getElementById('editCancel').addEventListener('click', hideEditModal);
  document.getElementById('genEditPwBtn').addEventListener('click', genEditPassword);

  // 导出/导入
  document.getElementById('exportBtn').addEventListener('click', function () {
    if (entries.length === 0) { alert('没有可导出的数据'); return; }
    showCryptoModal('export');
  });
  document.getElementById('importBtn').addEventListener('click', function () {
    document.getElementById('importEncFile').click();
  });
  document.getElementById('importEncFile').addEventListener('change', function () {
    if (this.files.length > 0) {
      pendingEncFile = this.files[0];
      this.value = '';
      showCryptoModal('import');
    }
  });
  document.getElementById('cryptoPwConfirm').addEventListener('click', handleCryptoConfirm);
  document.getElementById('cryptoPwCancel').addEventListener('click', hideCryptoModal);

  // 多选
  document.getElementById('selectAll').addEventListener('change', function () {
    selectAllToggle(this.checked);
  });
  document.getElementById('batchDelBtn').addEventListener('click', batchDelete);

  // 加载数据
  load(render);
});
