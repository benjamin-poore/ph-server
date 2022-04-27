var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../db/user-schema");
const Domain = require("../db/domain-schema");
const { check, validationResult } = require('express-validator');

/* GET users listing. */
const registerValidate = [
  check('url').isLength({ min: 3 })
    .withMessage('Url must be at least 3 characters')
    .matches('[a-zA-Z]+\..+').withMessage('must be in format "example.com"')
    .not().matches('www').withMessage('do not include "www"')
    .not().matches('http').withMessage('do not include "http" or "https" ')
    .matches('^[a-zA-Z0-9]').withMessage('must start with letter or number')
    .trim().escape()
];

router.post('/register', registerValidate, async (req, res) => {
  const { url, secret, ttlAccess, ttlRefresh } = req.body;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log("err")
    return res.status(422).send({ errors: errors.array() });
  }

  try {
    const domain = await Domain.findOne({url});
    if(domain){
      return res.status(404).send({ error: "Domain already registered" });
    }

    await Domain.create({
      url,
      secret,
      ttlAccess,
      ttlRefresh
    });
    return res.status(200).send({ msg: `Domain ${url} succesfully created` });
  } catch (err) {
    console.log(err);
    return res.status(500).send({ error: "Unable to create domain, please try again." });
  }
});

module.exports = router;
