/* import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors()); 

const PORT = process.env.PORT || 3000;

// Para simplificar, usaremos un array para almacenar usuarios
const users = [];

app.get('/', (req, res) => {
    res.send('Server is running');
  });
// Registro de usuario
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ username, password: hashedPassword });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user' });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { username, password} = req.body;
        const user = users.find(u => u.username === username);
        
        if (!user) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        const token = jwt.sign({ username: user.username}, process.env.JWT_SECRET, {expiresIn: '30m'});
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in' });        
    }
});

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    console.log('Auth Header:', authHeader);
    if (!authHeader) {
        return res.status(401).json({ message: 'No token provided' });
    }
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    console.log('Token:', token);
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err) {
            console.log('JWT Verify Error:', err);
            if(err.name === 'TokenExpiredError') {
                return res.status(401).json({message: 'Token expired'});
            }
            return res.status(401).json({message: 'Invalid token'});
        }
        req.user = decoded;
        console.log('Decoded Token:', decoded);
        next();
    });
};

// Ruta protegida para verificar el token
app.get('/verify', verifyToken, (req, res) => {
    console.log('User in request:', req.user);
    res.status(200).json({message: 'Token is valid', user: req.user})
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); */

// index.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { registeredUsuario, loginUsuario, getUsuario } from './controllers/usuarios.controller.js';
import { DB_SECRET_KEY } from './config/config.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.send('Server is running');
});

app.post('/api/auth/register', registeredUsuario);
app.post('/api/auth/login', loginUsuario);

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ message: 'No se proporcionó token' });
    }
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    jwt.verify(token, DB_SECRET_KEY, (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expirado' });
            }
            return res.status(401).json({ message: 'Token inválido' });
        }
        req.user = decoded;
        next();
    });
};

app.get('/api/auth/me', verifyToken, getUsuario);

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});