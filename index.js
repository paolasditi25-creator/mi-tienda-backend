// =====================================================================
//  BACKEND DE "MI TIENDA"  (la oficina central de la frutería 🍎)
//  Node.js + Express + Supabase
//
//  Ventanillas (endpoints) de la API:
//    GET    /                 -> revisar que el servidor está vivo
//    POST   /auth/register    -> registrarse (siempre como "usuario")
//    POST   /auth/login       -> iniciar sesión (devuelve token + rol)
//    GET    /usuarios         -> lista de usuarios       (solo admin)
//    DELETE /usuarios/:id     -> eliminar un usuario     (solo admin)
// =====================================================================
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());          // permite que la app (web, móvil, escritorio) nos hable
app.use(express.json());  // entiende los mensajes en formato JSON

// --- Conexión con la base de datos (el archivero) ---------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
  console.error('❌ Faltan variables: SUPABASE_URL, SUPABASE_KEY o JWT_SECRET');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Lo que sí se puede enseñar de un usuario (NUNCA el password)
const datosPublicos = (u) => ({
  id: u.id,
  nombre: u.nombre,
  usuario: u.usuario,
  rol: u.rol,
});

// --- Guardias de seguridad --------------------------------------------
// 1) Revisa que traigas una "pulsera" (token) válida
function verificarToken(req, res, next) {
  const encabezado = req.headers.authorization || '';
  const token = encabezado.startsWith('Bearer ') ? encabezado.slice(7) : null;
  if (!token) {
    return res.status(401).json({ mensaje: 'Falta el token' });
  }
  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ mensaje: 'Token inválido o vencido' });
  }
}

// 2) Revisa que tu pulsera sea de ADMINISTRADOR
function soloAdmin(req, res, next) {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Solo los administradores pueden hacer esto' });
  }
  next();
}

// --- Ventanillas (endpoints) ------------------------------------------

// Revisar que el servidor está vivo
app.get('/', (req, res) => {
  res.json({ mensaje: 'API de Mi Tienda funcionando 🍎' });
});

// REGISTRO: cualquiera se puede registrar, pero SIEMPRE como "usuario"
app.post('/auth/register', async (req, res) => {
  const nombre = (req.body.nombre || '').trim();
  const usuario = (req.body.usuario || '').trim().toLowerCase();
  const password = req.body.password || '';

  if (!nombre || !usuario || !password) {
    return res.status(400).json({ mensaje: 'Nombre, usuario y contraseña son obligatorios' });
  }
  if (password.length < 4) {
    return res.status(400).json({ mensaje: 'La contraseña debe tener al menos 4 caracteres' });
  }

  // Encriptamos la contraseña antes de guardarla
  const passwordEncriptado = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('usuarios')
    .insert({ nombre, usuario, password: passwordEncriptado, rol: 'usuario' })
    .select()
    .single();

  if (error) {
    if (error.code === '23505') {
      return res.status(409).json({ mensaje: 'Ese usuario ya existe' });
    }
    console.error(error);
    return res.status(500).json({ mensaje: 'Error al registrar' });
  }

  return res.status(201).json({ mensaje: 'Usuario registrado', usuario: datosPublicos(data) });
});

// LOGIN: revisa usuario y contraseña, y entrega token + rol
app.post('/auth/login', async (req, res) => {
  const usuario = (req.body.usuario || '').trim().toLowerCase();
  const password = req.body.password || '';

  if (!usuario || !password) {
    return res.status(400).json({ mensaje: 'Usuario y contraseña son obligatorios' });
  }

  const { data, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('usuario', usuario)
    .maybeSingle();

  if (error) {
    console.error(error);
    return res.status(500).json({ mensaje: 'Error del servidor' });
  }

  const passwordCorrecto = data ? await bcrypt.compare(password, data.password) : false;
  if (!data || !passwordCorrecto) {
    return res.status(401).json({ mensaje: 'Usuario o contraseña inválidos' });
  }

  // La "pulsera": dura 8 horas
  const token = jwt.sign(
    { id: data.id, usuario: data.usuario, rol: data.rol },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  return res.json({ token, usuario: datosPublicos(data) });
});

// LISTA DE USUARIOS (solo admin)
app.get('/usuarios', verificarToken, soloAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('usuarios')
    .select('id, nombre, usuario, rol')
    .order('id', { ascending: true });

  if (error) {
    console.error(error);
    return res.status(500).json({ mensaje: 'Error al obtener usuarios' });
  }
  return res.json(data.map(datosPublicos));
});

// ELIMINAR USUARIO (solo admin, y no puede borrarse a sí mismo)
app.delete('/usuarios/:id', verificarToken, soloAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ mensaje: 'ID inválido' });
  }
  if (id === req.usuario.id) {
    return res.status(400).json({ mensaje: 'No puedes eliminar tu propia cuenta' });
  }

  const { data, error } = await supabase
    .from('usuarios')
    .delete()
    .eq('id', id)
    .select();

  if (error) {
    console.error(error);
    return res.status(500).json({ mensaje: 'Error al eliminar' });
  }
  if (!data || data.length === 0) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado' });
  }
  return res.json({ mensaje: 'Usuario eliminado' });
});

app.listen(PORT, () => {
  console.log(`✅ Servidor de Mi Tienda escuchando en el puerto ${PORT}`);
});
