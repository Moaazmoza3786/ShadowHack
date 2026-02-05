const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());
const SECRET_KEY = 'moonbase'; 
app.get('/', (req, res) => {
    const token = req.cookies.auth;
    if (!token) {
        const guestToken = jwt.sign({ username: 'guest', role: 'guest' }, SECRET_KEY);
        res.cookie('auth', guestToken);
        return res.send('<h1>Welcome Guest. Status: Access Denied.</h1>');
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role === 'admin') {
            return res.send(\<h1>ADMIN ACCESS GRANTED!</h1><p>Flag: \</p>\);
        } else {
            return res.send(\<h1>Welcome \.</h1><p>Role: \</p><p>Status: Access Denied.</p>\);
        }
    } catch (e) { res.send('Invalid Token'); }
});
app.listen(3000, () => console.log('Server running on port 3000'));
