const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const NodeCache = require('node-cache');
const fs = require('fs'); 
const path = require('path'); 

const app = express();
const port = 3000;

const cache = new NodeCache({ stdTTL: 60 });


app.use(cookieParser());
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax' }
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let users = {};


app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('требуется имя пользователя и пароль');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    res.send('пользователь зарегестрирован');
});

// Авторизация пользователя
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('требуется имя пользователя и пароль');
    }
    const user = users[username];
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.username = username;

        // Создаем data.json при входе
        const data = {
            message: "данные созданная для пользователя " + username,
            lastUpdated: new Date().toISOString() // Добавляем время последнего обновления
        };
        fs.writeFileSync(path.join(__dirname, 'data.json'), JSON.stringify(data, null, 2));
        
        res.send('успешный вход');
    } else {
        res.status(401).send('неправильный пароль или иля пользователя');
    }
});

// Защищённый роут: доступ только для авторизованных пользователей
app.get('/profile', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/'); // Если не авторизован, перенаправляем на главную страницу
    }
    res.sendFile(path.join(__dirname, 'public', 'profile.html')); // Отправляем HTML файл профиля
});

// Выход из системы
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        res.send('успешный выход');
    });
});


app.get('/data', (req, res) => {    
    const cachedData = cache.get('data');

    if (cachedData) {
        return res.json(cachedData);
    }

    const newData = { message: 'Новые данные' };
    cache.set('data', newData);
    res.json(newData);
});


app.get('/data-file', (req, res) => {
    if (fs.existsSync(path.join(__dirname, 'data.json'))) {
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json')));
        data.lastUpdated = new Date().toISOString();
        fs.writeFileSync(path.join(__dirname, 'data.json'), JSON.stringify(data, null, 2));
        res.json(data);
    } else {
        res.status(404).send('Data file not found');
    }
});


app.use(express.static('public'));


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
