const request = require('supertest');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { describe, test, beforeEach, jest } = require('jest');
const User = require('../models/User');

const app = express();

app.use(express.json());

// Mock do modelo de usuário
jest.mock('../models/User', () => ({
  findOne: jest.fn(),
}));

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validação
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  // Simula a resposta do modelo de usuário (mock)
  const mockedUser = {
    _id: '123456789',
    email: 'test@example.com',
    password: bcrypt.hashSync('testpassword', 10),
  };

  User.findOne.mockReturnValueOnce(mockedUser);

  // Verifica a senha
  const checkPassword = await bcrypt.compare(password, mockedUser.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  // Gera o token (poderia ser mais complexo em uma aplicação real)
  const secret = 'secreto';
  const token = jwt.sign({ id: mockedUser._id }, secret);

  res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
});

describe('Testes para a rota de login', () => {
  test('Deve retornar status 422 se o email não for fornecido', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        password: 'testpassword',
      });

    expect(response.status).toBe(422);
    expect(response.body.msg).toBe("O email é obrigatório!");
  });

  test('Deve retornar status 422 se a senha não for fornecida', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
      });

    expect(response.status).toBe(422);
    expect(response.body.msg).toBe("A senha é obrigatória!");
  });

  test('Deve retornar status 422 se a senha for inválida', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'senhaerrada',
      });

    expect(response.status).toBe(422);
    expect(response.body.msg).toBe("Senha inválida");
  });

  test('Deve retornar status 200 e um token válido com credenciais corretas', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'testpassword',
      });

    expect(response.status).toBe(200);
    expect(response.body.msg).toBe("Autenticação realizada com sucesso!");
    expect(response.body.token).toBeDefined();
  });
});
