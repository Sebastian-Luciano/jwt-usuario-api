import { pool } from '../config/db.js';
import bcrypt from 'bcrypt';

const verifyUsuario = async (id) => {
  const [usuario] = await pool.execute(
    'SELECT usuario_id, nombre, email FROM usuario WHERE usuario_id = ?',
    [id]
  );
  return usuario[0];
};

const registerUsuario = async (nombre, email, password) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  const [resultado] = await pool.execute(
    'INSERT INTO usuario(nombre, email, password) VALUES (?, ?, ?)',
    [nombre, email, hashedPassword]
  );
  return resultado;
};

const findUsuarioByEmail = async (email) => {
  const [usuario] = await pool.execute(
    'SELECT * FROM usuario WHERE email = ?',
    [email]
  );
  return usuario[0];
};

export default { verifyUsuario, registerUsuario, findUsuarioByEmail };