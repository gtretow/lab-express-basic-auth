const router = require("express").Router();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const passport = require("passport");

const User = require("../models/User.model");

router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const errors = {};

  if (!username || typeof username !== "string" || username.length > 50) {
    errors.username = "Username is required and should be 50 characters max.";
  }

  // Tem que ser um email valido, é obrigatório
  if (!email || !email.match(/[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+/)) {
    errors.email = "Email is required and should be a valid email address";
  }

  if (
    !password ||
    !password.match(
      /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/
    )
  ) {
    errors.password =
      "Password is required, should be at least 8 characters long, should contain an uppercase letter, lowercase letter, a number and a special character";
  }

  // Se o objeto errors tiver propriedades (chaves), retorne as mensagens de erro
  if (Object.keys(errors).length) {
    return res.status(400).json({ errors });
  }

  try {
    // Gerar o salt

    const saltRounds = 10;

    const salt = await bcrypt.genSalt(saltRounds);

    // "Embaralhar" a senha enviada pelo usuário antes de salvar no banco
    const passwordHash = await bcrypt.hash(password, salt);

    // 4. Salvar o email e a senha criptografada no banco
    const result = await User.create({ email, username, passwordHash });

    console.log(result);

    return res.status(201).json(result);
  } catch (err) {
    console.error(err);
    // Mensagem de erro para exibir erros de validacao do Schema do Mongoose
    if (err instanceof mongoose.Error.ValidationError) {
      res.status(400).json({ error: err.message });
    } else if (err.code === 11000) {
      res.status(400).json({
        error:
          "Name and email need to be unique. Either username or email is already used.",
      });
    }
  }
});
// Next é uma função que passa algum valor para o próximo handler de rotas (do Express) da cadeia de handlers

router.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    // O objeto err só existe em caso de erro na comunicação com o Mongo
    if (err) {
      return res.status(500).json({ msg: err });
    }

    // Caso este email não esteja cadastrado ou a senha esteja divergente
    if (!user || info) {
      return res.status(401).json({ msg: info.message });
    }

    req.login(user, { session: false }, (err) => {
      if (err) {
        console.error(err);
        return next(err);
      }

      const { name, email } = user;
      return res.status(200).json({ name, email });
    });
  })(req, res, next);
});

module.exports = router;
