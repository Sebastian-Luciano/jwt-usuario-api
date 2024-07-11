import usuarioModel from '../models/Usuario.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { DB_SECRET_KEY } from '../config/config.js';

export const registeredUsuario = async (req, res) => {
    try {
        const { nombre, username, password } = req.body;
        if (!nombre || !username || !password) {
            return res.status(400).json({ message: 'Nombre, username y password son campos obligatorios' });
        }
        const resultado = await usuarioModel.registerUsuario(nombre, username, password);
        if (resultado.affectedRows !== 1) return res.status(500).json({ message: 'No se pudo insertar el usuario' });
        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al registrar usuario' });
    }
};

export const loginUsuario = async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await usuarioModel.findUsuarioByEmail(username);
        
        if (!user) {
            return res.status(401).json({ message: 'Autenticación fallida' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Autenticación fallida' });
        }

        const token = jwt.sign({ usuarioId: user.usuario_id }, DB_SECRET_KEY, { expiresIn: '30m' });
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al iniciar sesión' });        
    }
};

export const getUsuario = async (req, res) => {
    try {
        const usuario = await usuarioModel.verifyUsuario(req.user.usuarioId);
        if (!usuario) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        res.json(usuario);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al obtener información del usuario' });
    }
};