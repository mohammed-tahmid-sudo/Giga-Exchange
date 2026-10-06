const API_BASE = '/api';

const state = {
  token: localStorage.getItem('giga-token') || '',
  adminToken: localStorage.getItem('giga-admin-token') || '',
  user: null,
  wallet: null,
  transactions: [],
  activeView: 'login',
  qrPayload: '',
};

const els = {
  loginView: document.getElementById('login-view'),
  registerView: document.getElementById('register-view'),
  dashboardView: document.getElementById('dashboard-view'),
  profileView: document.getElementById('profile-view'),
  navLogin: document.getElementById('nav-login'),
  navRegister: document.getElementById('nav-register'),
  navDashboard: document.getElementById('nav-dashboard'),
  adminButton: document.getElementById('admin-button'),
  logoutBtn: document.getElementById('logout-btn'),
  welcomeName: document.getElementById('welcome-name'),
  balanceValue: document.getElementById('balance-value'),
  transactionList: document.getElementById('transaction-list'),
  profileDetails: document.getElementById('profile-details'),
  modal: document.getElementById('modal'),
  modalContent: document.getElementById('modal-content'),
};

function setView(name) {
  const views = ['login', 'register', 'dashboard', 'profile'];
  views.forEach((view) => {
    const target = document.getElementById(`${view}-view`);
    if (target) target.classList.toggle('active', view === name);
  });

  const loggedIn = !!state.token;
  els.navLogin.classList.toggle('hidden', loggedIn);
  els.navRegister.classList.toggle('hidden', loggedIn);
  els.navDashboard.classList.toggle('hidden', !loggedIn);
  els.logoutBtn.classList.toggle('hidden', !loggedIn);
  state.activeView = name;
}

function showMessage(parent, text, isError = false) {
  let msg = parent.querySelector('.message');
  if (!msg) {
    msg = document.createElement('div');
    msg.className = 'message';
    parent.appendChild(msg);
  }
  msg.className = `message ${isError ? 'error-message' : 'success-message'}`;
  msg.textContent = text;
}

async function apiRequest(path, options = {}, adminTokenOverride = '') {
  const headers = {
    Accept: 'application/json',
    ...(options.headers || {}),
  };

  if (!(options.body instanceof FormData) && !(options.body instanceof Blob)) {
    headers['Content-Type'] = 'application/json';
  }

  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  const adminToken = adminTokenOverride || state.adminToken;
  if (adminToken) {
    headers['X-Admin-Token'] = adminToken;
  }

  const res = await fetch(path, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = data?.error?.message || 'Request failed';
    throw new Error(message);
  }

  return data;
}

function formatMoney(cents) {
  const amount = Number((Number(cents) / 100).toFixed(2));
  return `${amount.toFixed(2)} GEX`;
}

function renderTransactions() {
  const list = els.transactionList;
  list.innerHTML = '';

  if (!state.transactions.length) {
    list.innerHTML = '<div class="empty-state">No transactions yet.</div>';
    return;
  }

  state.transactions.slice(0, 12).forEach((tx) => {
    const item = document.createElement('div');
    item.className = `transaction-item ${tx.direction === 'sent' ? 'sent' : 'received'}`;
    const label = tx.direction === 'sent' ? `Sent to ${tx.receiver?.username || 'user'}` : `Received from ${tx.sender?.username || 'user'}`;
    const amount = tx.direction === 'sent' ? `-${formatMoney(tx.amount_cents)}` : `+${formatMoney(tx.amount_cents)}`;
    item.innerHTML = `
      <div><strong>${label}</strong></div>
      <div class="transaction-meta">${tx.created_at}</div>
      <div class="transaction-amount">${amount}</div>
      <div class="transaction-meta">${tx.description || 'No description'}</div>
    `;
    list.appendChild(item);
  });
}

async function loadDashboard() {
  try {
    const [profile, walletRes, txRes] = await Promise.all([
      apiRequest(`${API_BASE}/users/me`),
      apiRequest(`${API_BASE}/wallet`),
      apiRequest(`${API_BASE}/transactions`),
    ]);

    state.user = profile.user;
    state.wallet = walletRes.data;
    state.transactions = txRes.data || [];

    els.welcomeName.textContent = `Hello, ${state.user.username}`;
    els.balanceValue.textContent = formatMoney(state.wallet.balance_cents);
    renderTransactions();
    setView('dashboard');
  } catch (error) {
    alert(error.message);
    logout();
  }
}

async function loadProfile() {
  try {
    const profile = await apiRequest(`${API_BASE}/users/me`);
    state.user = profile.user;
    const html = `
      <div><strong>Username:</strong> ${state.user.username}</div>
      <div><strong>Phone:</strong> ${state.user.phone_number}</div>
      <div><strong>Account ID:</strong> ${state.user.id}</div>
      <div><strong>Balance:</strong> ${formatMoney(profile.wallet.balance_cents)}</div>
    `;
    els.profileDetails.innerHTML = html;
    setView('profile');
  } catch (error) {
    alert(error.message);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const res = await apiRequest(`${API_BASE}/auth/login`, { method: 'POST', body: JSON.stringify(payload) });
    state.token = res.token;
    localStorage.setItem('giga-token', state.token);
    form.reset();
    await loadDashboard();
  } catch (error) {
    showMessage(form, error.message, true);
  }
}

async function handleRegister(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const res = await apiRequest(`${API_BASE}/auth/register`, { method: 'POST', body: JSON.stringify(payload) });
    showMessage(form, 'Account created successfully! You can now log in.', false);
    form.reset();
    setView('login');
  } catch (error) {
    showMessage(form, error.message, true);
  }
}

function openModal(content, closeable = true) {
  els.modalContent.innerHTML = content;
  els.modal.classList.remove('hidden');
  if (!closeable) return;
  document.getElementById('close-modal').onclick = () => els.modal.classList.add('hidden');
}

async function renderTransferModal() {
  const content = `
    <h2>Send money</h2>
    <form id="transfer-form">
      <label>Recipient
        <input name="recipient" type="text" placeholder="username, phone, or account id" required />
      </label>
      <label>Amount (GEX)
        <input name="amount" type="number" min="0.01" step="0.01" placeholder="25.00" required />
      </label>
      <label>Reference (optional)
        <input name="description" type="text" maxlength="200" placeholder="Dinner, rent, etc." />
      </label>
      <button type="submit">Confirm transfer</button>
    </form>
  `;
  openModal(content);
  document.getElementById('transfer-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      const res = await apiRequest(`${API_BASE}/transactions/transfer`, {
        method: 'POST',
        body: JSON.stringify({
          recipient: payload.recipient,
          amount: payload.amount,
          description: payload.description || '',
        }),
      });
      els.modal.classList.add('hidden');
      await loadDashboard();
      alert(res.message || 'Transfer completed');
    } catch (error) {
      const form = event.currentTarget;
      showMessage(form, error.message, true);
    }
  });
}

async function renderReceiveModal() {
  try {
    const res = await apiRequest(`${API_BASE}/qr/me`);
    const content = `
      <h2>Receive money</h2>
      <p>Share this QR code and your account ID.</p>
      <div class="qr-box"><img src="${res.data.qr_data_url}" alt="Payment QR code" style="max-width:100%; display:block; margin:0 auto;" /></div>
      <p>Payload: <small>${res.data.payload}</small></p>
    `;
    openModal(content);
  } catch (error) {
    alert(error.message);
  }
}

async function renderMyQRModal() {
  await renderReceiveModal();
}

async function startScanner() {
  const content = `
    <h2>Scan payment QR</h2>
    <video id="scan-video" class="scan-video" autoplay playsinline></video>
    <p id="scan-status">Allow camera access to scan a QR code.</p>
  `;
  openModal(content);

  const video = document.getElementById('scan-video');
  const status = document.getElementById('scan-status');

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    status.textContent = 'Camera access is not available on this device.';
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.srcObject = stream;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const tick = async () => {
      if (video.readyState >= 2) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
        if (code) {
          stream.getTracks().forEach((track) => track.stop());
          const payload = code.data;
          status.textContent = 'QR code detected. Resolving recipient...';
          try {
            const res = await apiRequest(`${API_BASE}/qr/resolve`, {
              method: 'POST',
              body: JSON.stringify({ payload }),
            });
            els.modal.classList.add('hidden');
            const recipient = res.user.username;
            openModal(`<h2>Recipient found</h2><p>${recipient}</p><form id="scan-transfer-form"><label>Amount (GEX)<input name="amount" type="number" step="0.01" required /></label><button type="submit">Send</button></form>`);
            document.getElementById('scan-transfer-form').addEventListener('submit', async (event) => {
              event.preventDefault();
              const amount = new FormData(event.currentTarget).get('amount');
              try {
                const result = await apiRequest(`${API_BASE}/transactions/transfer`, {
                  method: 'POST',
                  body: JSON.stringify({ recipient: `${res.user.id}`, amount, description: 'QR payment' }),
                });
                els.modal.classList.add('hidden');
                await loadDashboard();
                alert(result.message || 'Transfer completed');
              } catch (error) {
                showMessage(event.currentTarget, error.message, true);
              }
            });
          } catch (error) {
            status.textContent = error.message;
          }
          return;
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  } catch (error) {
    status.textContent = error.message;
  }
}

async function handlePasswordChange(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget).entries());
  try {
    const result = await apiRequest('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: data.current_password, new_password: data.new_password }),
    });
    showMessage(event.currentTarget, result.message || 'Password updated', false);
    event.currentTarget.reset();
  } catch (error) {
    showMessage(event.currentTarget, error.message, true);
  }
}

function logout() {
  state.token = '';
  state.user = null;
  state.wallet = null;
  localStorage.removeItem('giga-token');
  setView('login');
}

async function renderAdminModal() {
  const content = `
    <h2>Admin: add demo funds</h2>
    <form id="admin-fund-form">
      <label>Admin token
        <input name="admin_token" type="password" value="${state.adminToken}" placeholder="Enter admin token" required />
      </label>
      <label>Username
        <input name="username" type="text" placeholder="demo or merchant" required />
      </label>
      <label>Amount (GEX)
        <input name="amount" type="number" min="0.01" step="0.01" placeholder="100.00" required />
      </label>
      <button type="submit">Add funds</button>
    </form>
  `;
  openModal(content);

  const form = document.getElementById('admin-fund-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      state.adminToken = payload.admin_token;
      localStorage.setItem('giga-admin-token', state.adminToken);

      const amountValue = Number(payload.amount);
      const result = await apiRequest(
        `${API_BASE}/admin/demo-fund`,
        {
          method: 'POST',
          body: JSON.stringify({ username: payload.username, amount: amountValue }),
        },
        state.adminToken,
      );

      els.modal.classList.add('hidden');
      if (state.token) {
        await loadDashboard();
      }
      alert(result.message || 'Funds added successfully');
    } catch (error) {
      showMessage(event.currentTarget, error.message, true);
    }
  });
}

document.getElementById('login-form').addEventListener('submit', handleLogin);
document.getElementById('register-form').addEventListener('submit', handleRegister);
document.getElementById('show-register').addEventListener('click', (e) => { e.preventDefault(); setView('register'); });
document.getElementById('show-login').addEventListener('click', (e) => { e.preventDefault(); setView('login'); });
document.getElementById('nav-login').addEventListener('click', () => setView('login'));
document.getElementById('nav-register').addEventListener('click', () => setView('register'));
document.getElementById('nav-dashboard').addEventListener('click', () => loadDashboard());
document.getElementById('admin-button').addEventListener('click', renderAdminModal);
document.getElementById('logout-btn').addEventListener('click', logout);
document.getElementById('send-button').addEventListener('click', renderTransferModal);
document.getElementById('receive-button').addEventListener('click', renderReceiveModal);
document.getElementById('scan-button').addEventListener('click', startScanner);
document.getElementById('my-qr-button').addEventListener('click', renderMyQRModal);
document.getElementById('profile-button').addEventListener('click', loadProfile);
document.getElementById('close-modal').addEventListener('click', () => els.modal.classList.add('hidden'));
document.getElementById('password-form').addEventListener('submit', handlePasswordChange);

if (state.token) {
  loadDashboard();
} else {
  setView('login');
}
