const express = require('express');
const router = express.Router();
const getConnection = require('../conexion');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

router.post('/login', [
  body('username').notEmpty().withMessage('El nombre de usuario es requerido'),
  body('password').notEmpty().withMessage('La contraseña es requerida'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Verificar el usuario y la contraseña en la base de datos
  getConnection((err, conn) => {
    if (err) {
      console.log("No se puede conectar a la base de datos " + err);
      return res.sendStatus(500);
    }
    const query = 'SELECT * FROM usuarios WHERE username = ?';
    conn.query(query, [username], (err, rows) => {
      if (err) {
        console.log("Error en consulta: " + err);
        conn.release();
        return res.sendStatus(500);
      }

      if (rows.length === 0) {
        conn.release();
        return res.status(401).json({ message: 'Usuario no encontrado' });
      }

      const user = rows[0];
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          console.log("Error al comparar contraseñas: " + err);
          conn.release();
          return res.sendStatus(500);
        }

        if (result) {
          // Contraseña válida, generar token de autenticación
          const token = jwt.sign({ userId: user.id }, 'secretKey', { expiresIn: '1h' });
          conn.release();
          return res.json({ token });
        } else {
          conn.release();
          return res.status(401).json({ message: 'Contraseña incorrecta' });
        }
      });
    });
  });
});

router.post('/register', [
  body('username').notEmpty().withMessage('El nombre de usuario es requerido'),
  body('password').notEmpty().withMessage('La contraseña es requerida'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Verificar que el usuario no exista previamente en la base de datos
  getConnection((err, conn) => {
    if (err) {
      console.log("No se puede conectar a la base de datos " + err);
      return res.sendStatus(500);
    }
    const query = 'SELECT * FROM usuarios WHERE username = ?';
    conn.query(query, [username], (err, rows) => {
      if (err) {
        console.log("Error en consulta: " + err);
        conn.release();
        return res.sendStatus(500);
      }

      if (rows.length > 0) {
        conn.release();
        return res.status(409).json({ message: 'El usuario ya existe' });
      }

      // Si el usuario no existe, crear el registro en la base de datos
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.log("Error al generar el hash de contraseña: " + err);
          conn.release();
          return res.sendStatus(500);
        }

        const insertQuery = 'INSERT INTO usuarios (username, password) VALUES (?, ?)';
        conn.query(insertQuery, [username, hashedPassword], (err, result) => {
          if (err) {
            console.log("Error al insertar el usuario en la base de datos: " + err);
            conn.release();
            return res.sendStatus(500);
          }
          conn.release();
          return res.json({ message: 'Registro exitoso' });
        });
      });
    });
  });
});

module.exports = router;
