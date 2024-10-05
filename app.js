// imports
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// config json

app.use(express.json());

//models
const User = require("./models/User");

// Open Route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API" });
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // check user

  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({msg:"Usuario nao encontrado"});
  }

  res.status(200).json({user})
});

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg:"Acesso negado"})

    }

    try {
            
        const secret = process.env.SECRET

        jwt.verify((token, secret))

        next()

    } catch (error) {
        res.status(400).json({msg:"Token Invalido"})
    }

}

// Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  //validation

  if (!name) {
    return res.status(422).json({ msg: "O nome e obrigatorio" });
  }

  if (!email) {
    return res.status(422).json({ msg: "O email e obrigatorio" });
  }

  if (!password) {
    return res.status(422).json({ msg: "O senha e obrigatoria" });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "As senhas nao coincidem" });
  }

  //check user exist

  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "O email pertence a outro usuario" });
  }

  // create password

  const salt = await bcrypt.genSalt(12); //adicionar digitos
  const passwordHash = await bcrypt.hash(password, salt);

  // create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Usuario criado com sucesso!" });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      msg: "Aconteceu um erro no servidor, tente novamente mais tarde",
    });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validation

  if (!email) {
    res.status(201).json({ msg: "O email e obrigatorio" });
  }

  if (!password) {
    res.status(201).json({ msg: "A senha e obrigatoria" });
  }

  // check user

  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usuario nao encontrado" });
  }

  // check password

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha invalida" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticacao realizada com sucesso", token });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      msg: "Aconteceu um erro no servidor, tente novamente mais tarde",
    });
  }
});

//Credentials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@auth.kn6oe.mongodb.net/?retryWrites=true&w=majority&appName=Auth`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectado ao banco!");
  })
  .catch((err) => console.log(err));
