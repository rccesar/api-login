require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// models
const User = require("./models/User");

// Configurar resposta JSON
app.use(express.json());

// Rota publica
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a API!" });
});

// Rota privada
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // Verifica se o usuário existe
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado!" });

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    res.status(400).json({ msg: "O Token é inválido!" });
  }
}

//Registro do usuário
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  // Validação
  if (!name) {
    return res.status(422).json({ msg: "Nome é obrigatório !" });
  }

  if (!email) {
    return res.status(422).json({ msg: "E-mail é obrigatório !" });
  }

  if (!password) {
    return res.status(422).json({ msg: "Senha é obrigatória !" });
  }

  if (password != confirmpassword) {
    return res
      .status(422)
      .json({ msg: "Senha e a confirmação precisam ser iguais !" });
  }

  // Verifica se o usuário existe
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "E-mail ja cadastrado, utilize outro e-mail !" });
  }

  // Criação da senha com hash
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Criação do user
  const user = new User({
    name,
    email,
    passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    res.status(500).json({ msg: error });
  }
});

// Login do Usuário
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validação
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  // Verifica o usuario
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  // Verifica a senha
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    res.status(500).json({ msg: error });
  }
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;


//Conexão com o mangoDB
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.folvv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
  )
  .then(() => {
    console.log("Conectou ao banco!");
    app.listen(3000);
  })
  .catch((err) => console.log(err));