const express = require('express');
const prisma = require('@prisma/client').PrismaClient;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const cors = require('cors');

const app = express();
const prismaClient = new prisma();

// Middleware
app.use(express.json());
app.use(cors());

// Configurações do JWT
const JWT_SECRET = 'seuSegredoAqui'; // Alterar para uma chave mais segura

// Função para gerar JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
}

// Rota de Registro
app.post('/api/register', async (req, res) => {
  const { nome, email, senha } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(senha, 10);

    const newUser = await prismaClient.user.create({
      data: {
        name: nome,
        email: email,
        password: hashedPassword
      }
    });

    const token = generateToken(newUser);
    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
});

// Rota de Login
app.post('/api/authenticate', async (req, res) => {
  const { email, senha } = req.body;

  try {
    const user = await prismaClient.user.findUnique({
      where: { email: email }
    });

    if (!user) {
      return res.status(400).json({ error: 'Usuário não encontrado.' });
    }

    const validPassword = await bcrypt.compare(senha, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Senha incorreta.' });
    }

    const token = generateToken(user);
    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao autenticar.' });
  }
});

// Middleware de autenticação
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ error: 'Token não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido.' });
    }
    req.user = decoded;
    next();
  });
};

// Rota para comentar
app.post('/api/comment', authenticate, async (req, res) => {
  const { content } = req.body;
  const userId = req.user.id;

  try {
    const comment = await prismaClient.comment.create({
      data: {
        content: content,
        userId: userId
      }
    });
    res.status(201).json({ comment });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao comentar.' });
  }
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});
