const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = 3000;

const MONGODB_URI = 'mongodb+srv://khafaa:<db_password>@khafaa.bjrqymt.mongodb.net/?retryWrites=true&w=majority&appName=khafaa';
const SESSION_SECRET = 'SECRET_KEY_SESSION_NOKOS_APP_ULTRA_PRO';
const DEFAULT_VIRTUSIM_API_KEY = 'hmxBcXyHbPs2gtndSiL3C4rZEW50jl'; // PASTIKAN INI VALID
const VIRTUSIM_API_BASE_URL = 'https://virtusim.com/api/v2/json.php';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    userApiKey: { type: String, trim: true, default: '' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.status(401).json({ success: false, message: 'Akses ditolak. Silakan login.' });
}

async function callVirtuSIMAPI(params) {
    try {
        // console.log("Calling VirtuSIM with params:", params); 
        const response = await axios.get(VIRTUSIM_API_BASE_URL, { params });
        // console.log("VirtuSIM Raw Response for action", params.action, ":", JSON.stringify(response.data, null, 2));

        if (response.data) {
            const isSuccess = response.data.response === "1" ||
                              response.data.status === "success" ||
                              response.data.status === true ||
                              response.data.status === "SUCCESS" ||
                              response.data.msg === "SUCCESS";
            
            if (isSuccess || (response.data.status_code && response.data.status_code === 200) ) {
                return { success: true, data: response.data };
            } else {
                const errorMessage = response.data.msg || response.data.message || response.data.error || 'Operasi gagal atau API Key/parameter tidak valid.';
                // console.error("VirtuSIM logical error:", errorMessage, "Full VirtuSIM response:", response.data);
                return { success: false, message: errorMessage, data: response.data };
            }
        }
        // console.error("No response.data from VirtuSIM for params:", params);
        return { success: false, message: 'Respons tidak valid dari VirtuSIM (tidak ada data).' };
    } catch (error) {
        // console.error("VirtuSIM API Call Axios Error:", error.message, "Params:", params);
        let message = 'Gagal terhubung ke layanan VirtuSIM.';
        if (error.response && error.response.data) {
            message = error.response.data.message || error.response.data.msg || message;
        }
        return { success: false, message: message };
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Username dan password (minimal 6 karakter) diperlukan.' });
    }
    try {
        const existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Username sudah digunakan.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username: username.toLowerCase(), password: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username dan password diperlukan.' });
    }
    try {
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Kredensial tidak valid.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Kredensial tidak valid.' });
        }
        req.session.userId = user._id;
        req.session.username = user.username;
        res.json({ success: true, message: 'Login berhasil!', user: { username: user.username, apiKey: user.userApiKey } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) { return res.status(500).json({ success: false, message: 'Gagal logout.' }); }
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logout berhasil.' });
    });
});

app.get('/api/session', async (req, res) => {
    if (req.session.userId) {
        try {
            const user = await User.findById(req.session.userId).select('-password');
            if (user) {
                res.json({ success: true, loggedIn: true, user: { username: user.username, apiKey: user.userApiKey } });
            } else {
                req.session.destroy();
                res.json({ success: false, loggedIn: false });
            }
        } catch (error) { res.status(500).json({ success: false, loggedIn: false, message: 'Server error' });}
    } else {
        res.json({ success: false, loggedIn: false });
    }
});

app.post('/api/profile/update-apikey', isAuthenticated, async (req, res) => {
    const { apiKey } = req.body;
    if (typeof apiKey !== 'string') {
        return res.status(400).json({ success: false, message: 'API Key diperlukan.' });
    }
    try {
        const updatedUser = await User.findByIdAndUpdate(req.session.userId, { userApiKey: apiKey.trim() }, { new: true }).select('-password');
        res.json({ success: true, message: 'API Key berhasil diperbarui.', user: { username: updatedUser.username, apiKey: updatedUser.userApiKey }});
    } catch (error) {
        res.status(500).json({ success: false, message: 'Gagal memperbarui API Key.' });
    }
});

app.get('/api/profile/balance', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(400).json({ success: false, message: 'API Key pengguna belum diatur.' });
    }
    const result = await callVirtuSIMAPI({ api_key: user.userApiKey, action: 'balance' });
    res.json(result);
});

app.get('/api/profile/balance-logs', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(400).json({ success: false, message: 'API Key pengguna belum diatur.' });
    }
    const result = await callVirtuSIMAPI({ api_key: user.userApiKey, action: 'balance_logs' });
    res.json(result);
});

app.post('/api/profile/deposit', isAuthenticated, async (req, res) => {
    const { method, amount, phone } = req.body;
    if (!method || !amount || !phone) {
        return res.status(400).json({ success: false, message: 'Metode, jumlah, dan nomor telepon deposit diperlukan.'});
    }
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(400).json({ success: false, message: 'API Key pengguna belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'deposit',
        method: method,
        amount: amount,
        phone: phone
    });
    res.json(result);
});

app.get('/api/countries', async (req, res) => {
    const result = await callVirtuSIMAPI({ api_key: DEFAULT_VIRTUSIM_API_KEY, action: 'list_country' });
    res.json(result);
});

app.get('/api/services', async (req, res) => {
    const { country } = req.query;
    if (!country) {
        return res.status(400).json({ success: false, message: 'Parameter negara diperlukan.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: DEFAULT_VIRTUSIM_API_KEY,
        action: 'services',
        country: country,
        service: ''
    });
    res.json(result);
});

app.get('/api/operators', async (req, res) => {
    const { country } = req.query;
    if (!country) {
        return res.status(400).json({ success: false, message: 'Parameter negara diperlukan.' });
    }
    const result = await callVirtuSIMAPI({ api_key: DEFAULT_VIRTUSIM_API_KEY, action: 'list_operator', country: country });
    res.json(result);
});

app.post('/api/order', isAuthenticated, async (req, res) => {
    const { service_id, country, operator = 'any' } = req.body;
    if (!service_id || !country) {
        return res.status(400).json({ success: false, message: 'ID Layanan dan Negara diperlukan.' });
    }
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'order',
        service: service_id,
        operator: operator,
        country: country
    });
    res.json(result);
});

app.get('/api/order/status/:orderId', isAuthenticated, async (req, res) => {
    const { orderId } = req.params;
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'status',
        id: orderId
    });
    res.json(result);
});

app.post('/api/order/set-status/:orderId', isAuthenticated, async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;
    if (!status) {
        return res.status(400).json({ success: false, message: 'Parameter status diperlukan.' });
    }
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'set_status',
        id: orderId,
        status: status
    });
    res.json(result);
});

app.get('/api/order/active', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({ api_key: user.userApiKey, action: 'active_order' });
    res.json(result);
});

app.get('/api/order/history', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({ api_key: user.userApiKey, action: 'order_history' });
    res.json(result);
});

app.get('/api/order/detail/:orderId', isAuthenticated, async (req, res) => {
    const { orderId } = req.params;
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'detail_order',
        id: orderId
    });
    res.json(result);
});

app.post('/api/order/reactivate/:orderId', isAuthenticated, async (req, res) => {
    const { orderId } = req.params;
    const user = await User.findById(req.session.userId);
    if (!user || !user.userApiKey) {
        return res.status(403).json({ success: false, message: 'API Key pengguna tidak valid atau belum diatur.' });
    }
    const result = await callVirtuSIMAPI({
        api_key: user.userApiKey,
        action: 'reactive_order',
        id: orderId
    });
    res.json(result);
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
