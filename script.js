const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const app = express();
const port = 3000;

// Configurar o banco de dados
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'login',
});

// Configurar express-session
app.use(session({
  secret: 'seu_segredo',
  resave: true,
  saveUninitialized: true,
}));

// Configurar o mecanismo de visualização
app.set('view engine', 'ejs');

// Configurar o middleware para analisar o corpo das solicitações
app.use(bodyParser.urlencoded({ extended: true }));

// Configurar flash para mensagens
app.use(flash());

// Configurar o passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  (username, password, done) => {
    connection.query('SELECT * FROM usuarios WHERE username = ?', [username], (err, results) => {
      if (err) throw err;

      if (results.length === 0) {
        return done(null, false, { message: 'Usuário não encontrado.' });
      }

      const user = results[0];

      bcrypt.compare(password, user.password, (err, match) => {
        if (err) throw err;

        if (match) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Senha incorreta.' });
        }
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  connection.query('SELECT * FROM usuarios WHERE id = ?', [id], (err, results) => {
    if (err) throw err;
    const user = results[0];
    done(null, user);
  });
});




// Rota para o formulário de registro
app.get('/register', (req, res) => {
    res.render('register', { message: req.flash('error') });
  });
  
  // Rota para processar o formulário de registro
  app.post('/register', async (req, res) => {
    const { username, password } = req.body;
  
    // Hash da senha usando bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Inserir usuário no banco de dados
    connection.query('INSERT INTO usuarios (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
          console.error('Erro ao registrar usuário:', err);
          req.flash('error', 'Erro ao registrar usuário.');
          res.redirect('/register');
        } else {
          res.redirect('/login');
        }
      });
  });





// Rotas para registro, login e logout

app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.listen(port, () => {
  console.log(`Servidor está rodando em http://localhost:${port}`);
});
