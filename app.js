// =====================================================
// GOLDOFFER — CLIENT APP LOGIC
// =====================================================

const API_BASE = 'https://onrender.com';

// --- ИНИЦИАЛИЗАЦИЯ ПРИ ЗАРЕЖДАНЕ НА СТРАНИЦАТА ---
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('goldoffer_token');

    // Логика за Регистрация
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    // Логика за Вход
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Логика за Таблото (Dashboard)
    if (document.getElementById('offersList')) {
        if (!token) {
            window.location.href = 'login.html';
            return;
        }
        loadDashboardData();
    }

    // Логика за Публична Оферта
    if (document.getElementById('publicOfferContainer')) {
        loadPublicOffer();
    }
});

// --- 1. РЕГИСТРАЦИЯ ---
async function handleRegister(e) {
    e.preventDefault();
    const errorMsg = document.getElementById('errorMsg');
    errorMsg.innerText = '';

    const name = document.getElementById('name').value;
    const businessName = document.getElementById('businessName').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, businessName, email, password })
        });

        const data = await res.json();

        if (!res.ok) throw new Error(data.message || 'Грешка при регистрация');

        localStorage.setItem('goldoffer_token', data.token);
        window.location.href = 'dashboard.html';
    } catch (err) {
        errorMsg.innerText = err.message;
    }
}

// --- 2. ВХОД ---
async function handleLogin(e) {
    e.preventDefault();
    const errorMsg = document.getElementById('errorMsg');
    errorMsg.innerText = '';

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (!res.ok) throw new Error(data.message || 'Грешка при вход');

        localStorage.setItem('goldoffer_token', data.token);
        window.location.href = 'dashboard.html';
    } catch (err) {
        errorMsg.innerText = err.message;
    }
}

// --- 3. ЗАРЕЖДАНЕ НА ДАННИ В ТАБЛОТО ---
async function loadDashboardData() {
    const token = localStorage.getItem('goldoffer_token');

    try {
        // Вземане на профила
        const userRes = await fetch(`${API_BASE}/auth/me`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const userData = await userRes.json();

        if (userRes.ok) {
            document.getElementById('userBusiness').innerText = userData.businessName;
            document.getElementById('subscriptionStatus').innerText = userData.subscriptionStatus;
        }

        // Вземане на офертите
        const offersRes = await fetch(`${API_BASE}/offers`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const offers = await offersRes.json();

        const offersList = document.getElementById('offersList');
        if (offers.length === 0) {
            offersList.innerHTML = '<p class="empty-msg">Все още нямате създадени оферти.</p>';
            return;
        }

        offersList.innerHTML = offers.map(offer => `
            <div class="offer-card">
                <div>
                    <h3>${offer.title}</h3>
                    <p>Цена: ${offer.price} BGN | Статус: ${offer.status}</p>
                </div>
                <a href="offer.html?id=${offer.shortId}" class="secondary-btn" target="_blank">Преглед</a>
            </div>
        `).join('');

    } catch (err) {
        console.error('Грешка при зареждане:', err);
    }
}

// --- 4. ЗАРЕЖДАНЕ НА ПУБЛИЧНА ОФЕРТА ---
async function loadPublicOffer() {
    const urlParams = new URLSearchParams(window.location.search);
    const offerId = urlParams.get('id');
    const container = document.getElementById('publicOfferContainer');

    if (!offerId) {
        container.innerHTML = '<p class="empty-msg">Невалиден линк към оферта.</p>';
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/offers/public/${offerId}`);
        const offer = await res.json();

        if (!res.ok) throw new Error('Офертата не е намерена');

        container.innerHTML = `
            <div class="offer-header">
                <h2>${offer.title}</h2>
                <p class="eyebrow">${offer.businessName}</p>
            </div>
            <div class="offer-body">
                <p>${offer.description}</p>
                <h3>Крайна цена: ${offer.price} BGN</h3>
            </div>
            <button class="gold-btn full-width" onclick="alert('Офертата е приета!')">
                Приемам офертата
            </button>
        `;
    } catch (err) {
        container.innerHTML = `<p class="empty-msg">${err.message}</p>`;
    }
}

// --- 5. ИЗХОД ---
function logout() {
    localStorage.removeItem('goldoffer_token');
    window.location.href = 'index.html';
}