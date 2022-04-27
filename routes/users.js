var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../db/user-schema");
const { check, validationResult } = require('express-validator');
const jwt = require("jsonwebtoken");

/* GET users listing. */
const registerValidate = [
  check('email', 'Username Must Be an Email Address').isEmail().trim().escape().normalizeEmail(),
  check('password').isLength({ min: 8 })
    .withMessage('Password Must Be at Least 8 Characters')
    .matches('[0-9]').withMessage('Password Must Contain a Number')
    .matches('[A-Z]').withMessage('Password Must Contain an Uppercase Letter')
    .trim().escape()
];

router.post('/register', registerValidate, async (req, res) => {
  const { email, password, url } = req.body;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log("err")
    return res.status(422).json({ errors: errors.array() });
  }

  try {
    await User.create({
      email,
      password: bcrypt.hashSync(password, 8),
    });
    return res.status(200).json({ msg: `User ${email} succesfully created` });
  } catch (err) {
    console.log(err);
    if (err?.code == 11000) {
      return res.status(409).json({ error: "Email in use. Please either log in or use a different email." });
    }
    return res.status(500).json({ error: "Unable to create user, please try again." });
  }
});

router.post('/login', async (req, res) => {
  const { email, password, url } = req.body;
  const errors = validationResult(req);
  const cookies = req.cookies;
  console.log(`cookie available at login: ${JSON.stringify(cookies)}`);

  const user = await User.findOne({ email, url })

  if (!user) {
    return res.status(404).json({ error: "Account not found" });
  }

  const validPassword = bcrypt.compareSync(password, user.password);
  if (validPassword) {


    const accessToken = jwt.sign(
      {
        "UserInfo": {
          "email": user.email,
          "role": user.role

        }
      },
      process.env.SECRET,
      { expiresIn: '10s' }
      // { expiresIn: user.domain.ttlAccess }

    );
    const newRefreshToken = jwt.sign(
      { "email": user.email },
      process.env.REFRESH_SECRET,
      { expiresIn: '1d' }
    );

    let newRefreshTokenArray =
      !cookies?.jwt
        ? user.refreshToken
        : user.refreshToken.filter(rt => rt !== cookies.jwt);

    if (cookies?.jwt) {
      const refreshToken = cookies.jwt;
      const foundToken = await User.findOne({ refreshToken }).exec();

      if (!foundToken) {
        console.log('attempted refresh token reuse at login!')
        newRefreshTokenArray = [];
      }

      res.clearCookie('jwt', { httpOnly: true, secure: true });
    }

    // Saving refreshToken with current user
    user.refreshToken = [...newRefreshTokenArray, newRefreshToken];
    const result = await user.save();


    // Creates Secure Cookie with refresh token
    // res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, maxAge: 24 * 60 * 60 * 1000 });
    res.cookie('jwt', newRefreshToken, { maxAge: 24 * 60 * 60 * 1000 });


    // Send authorization roles and access token to user
    console.log(accessToken)
    res.json({ result, accessToken });

  } else {
    return res.status(401).json({ error: "Incorrect password", accessToken: null });
  }

});

router.post('/refresh', registerValidate, async (req, res) => {

  const cookies = req.cookies;
  const { url } = req.body; 
  if (!cookies?.jwt){
    console.log("missing jwt cookie");
    return res.jsonStatus(401);
  } 
  const refreshToken = cookies.jwt;
  res.clearCookie('jwt', { httpOnly: true, secure: true });

  let user = await User.findOne({ refreshToken }).exec();


  // Detected refresh token reuse!
  if (!user) {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_SECRET,
      async (err, decoded) => {
        user = await User.findOne({ email: decoded.email }).exec();
        // if (err) return res.jsonStatus(403); //Forbidden
        console.log('attempted refresh token reuse!')
        user.refreshToken = [];
        const result = await user.save();
        console.log(result);
      }
    )
    console.log("DETECTED REFRESH OR ERROR")
    return res.jsonStatus(403); //Forbidden
  }

  const newRefreshTokenArray = user.refreshToken.filter(rt => rt !== refreshToken);

  // evaluate jwt 
  jwt.verify(
    refreshToken,
    process.env.REFRESH_SECRET,
    async (err, decoded) => {
      if (err) {
        console.log(err)
        user.refreshToken = [...newRefreshTokenArray];
        const result = await user.save();
        console.log(result);
      }
      if (err || user.email !== decoded.email){
        console.log(err);
        console.log(user.email)
        console.log(decoded)
        return res.jsonStatus(403);
      } 

      // Refresh token was still valid
      const roles = Object.values(user.role);
      const accessToken = jwt.sign(
        {
          "UserInfo": {
            "email": decoded.email,
            "roles": roles
          }
        },
        process.env.SECRET,
        { expiresIn: '10s' }
      );

      const newRefreshToken = jwt.sign(
        { "email": user.email },
        process.env.REFRESH_SECRET,
        { expiresIn: '1d' }
      );
      // Saving refreshToken with current user
      user.refreshToken = [...newRefreshTokenArray, newRefreshToken];
      const result = await user.save();

      // Creates Secure Cookie with refresh token
      // res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
      res.cookie('jwt', newRefreshToken, {  maxAge: 24 * 60 * 60 * 1000 });
      res.json({ roles, accessToken })
    }
  );
});

router.post('/logout', async (req,res) =>{
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.jsonStatus(204); //No content
  const refreshToken = cookies.jwt;

  // Is refreshToken in db?
  const user = await User.findOne({ refreshToken }).exec();
  if (!user){
      res.clearCookie('jwt', { httpOnly: true, secure: true });
      return res.jsonStatus(204);
  }

  // Delete refreshToken in db
  user.refreshToken = user.refreshToken.filter(rt => rt !== refreshToken);;
  const result = await user.save();
  console.log(result);

  res.clearCookie('jwt', { httpOnly: true, secure: true });
  res.jsonStatus(204);
});


module.exports = router;
