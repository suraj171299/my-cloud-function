import express from 'express';
import session from 'express-session';
import passport from 'passport';
import rateLimit from 'express-rate-limit';
import 'dotenv/config'; 
import './auth.js';

const app = express();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
});

app.use(limiter);
const isLoggedIn = (req, res, next) => {
  req.user ? next() : res.sendStatus(401);
};

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send('<a href="/auth/google">Login with Gmail</a>');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['email', 'profile'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/protected',
    failureRedirect: '/auth/google/failure'
  })
);

app.get('/protected', isLoggedIn, limiter, (req, res) => {
  res.send(`Hello ${req.user.displayName}. You are logged in with Gmail account`);
});

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      res.send('You have been logged out');
    });
  });
});

app.get('/auth/google/failure', (req, res) => {
  res.send('Failed to login.');
});

app.listen(process.env.PORT || 4000, () => console.log('listening on port: 4000'));

export {app};
