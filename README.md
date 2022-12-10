Entregable #05 NodeJS - Proyecto rutas protegidas
https://academlo.notion.site/Proyecto-Rutas-Protegidas-833dbfc03dec4e36bf7085190f0daf8b

Rutas No Protegidas:
-------------------
GET    http://localhost:9000/
GET    http://localhost:9000/api/v1/users
POST   http://localhost:9000/api/v1/users
GET    http://localhost:9000/api/v1/users/:id
POST   http://localhost:9000/api/v1/auth/login

Rutas Protegidas:
----------------
PATCH   http://localhost:9000/api/v1/users/:id
DELETE  http://localhost:9000/api/v1/users/:id
-------------------------------------------------------------
Terminal
-------------------------------------------------------------
npm install
npm install bcrypt uuid passport passport-jwt jsonwebtoken
-------------------------------------------------------------
.env
-------------------------------------------------------------
PORT=9000
DB_USER = postgres
DB_PASSWORD = root
DB_HOST = localhost
DB_PORT = 5432
DB_NAME = blogweb
JWT_SECRET = ac4deml0v3rs
-------------------------------------------------------------
src/utils/crypto.js
-------------------------------------------------------------
const bcrypt = require('bcrypt')
const hashPassword = (plainPassword) => {   //* Password Encryption
  return bcrypt.hashSync(plainPassword, 10)
}
const comparePassword = (plainPassword, hashedPassword) => { //* Encrypted Password Validation
  return bcrypt.compareSync(plainPassword, hashedPassword)
}
module.exports = {
  hashPassword,
  comparePassword
}
-------------------------------------------------------------
src/users/users.controllers.js
-------------------------------------------------------------
const { hashPassword } = require ('../utils/crypto')
...
password: hashPassword(obj.password), // change password attribute of the object argument in Users.create method
...
const findUserByEmail = async (email) => {
    const data = await Users.findOne({
        where: {
            email: email
        }
    })
    return data
}
module.exports = {
    findAllUsers,
    findUserById,
    createUser,
    updateUser,
    deleteUser,
    findUserByEmail
}
-------------------------------------------------------------
src/auth/auth.controller.js
-------------------------------------------------------------
const { findUserByEmail } = require('../users/users.controllers');
const { comparePassword } = require('../utils/crypto')
const checkUserCredential = async (email, password) => {
  try {
      const user = await findUserByEmail(email)
      const verifyPassword = comparePassword(password, user.password)
      if (verifyPassword) {
          return user
      }
      return null
  } catch (error) {
      return null
  }
}
module.exports = checkUserCredential;
-------------------------------------------------------------
src/auth/auth.services.js
-------------------------------------------------------------
const jwt = require('jsonwebtoken')
const checkUserCredential = require('./auth.controller')
const jwtSecret = require('../../config').api.jwtSecret
const postLogin = (req, res) => {
  const { email, password } = req.body
  if (email && password) {
    checkUserCredential(email, password)
      .then((data) => {
        if (data) {
          const token = jwt.sign({
            id: data.id,
            user_name: data.user_name,
            role: data.role
          }, jwtSecret)
          res.status(200).json({
            message: 'Correct Credentials',
            token
          })
        } else {
          res.status(401).json({ message: 'Invalid Credentials' })
        }
      })
      .catch((err) => {
        res.status(400).json({ message: err.message })
      })
  } else {
    res.status(400).json({ message: 'Missing Data', fields: { email: 'example@example.com', password: 'string' } })
  }
}
module.exports = {
  postLogin
}
-------------------------------------------------------------
src/auth/auth.router.js
-------------------------------------------------------------
const router = require('express').Router()
const authServices = require('./auth.services')
router.post('/login', authServices.postLogin)
module.exports = router
-------------------------------------------------------------
src/middleware/auth.middleware.js
-------------------------------------------------------------
const JwtStrategy = require("passport-jwt").Strategy
const ExtractJwt = require("passport-jwt").ExtractJwt
const passport = require("passport")
const jwtSecret = require("../../config").api.jwtSecret;
const { findUserById } = require("../users/users.controllers")
const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("jwt"),
  secretOrKey: jwtSecret
}
passport.use(
  new JwtStrategy(options, async (tokenDecoded, done) => {
    try {
      const user = await findUserById(tokenDecoded.id);
      if (user) {
        return done(null, tokenDecoded)  //* done(error, tokenDecoded)
      } else {
        return done(null, false)
      }
    } catch (error) {
      return done(error, false)
    }
  })
);
module.exports = passport
-------------------------------------------------------------
src/users/users.router.js
-------------------------------------------------------------
...
const passportJWT = require('../middleware/auth.middleware')
...
router.patch('/:id', passportJWT.authenticate('jwt', { session: false }), userServices.patchUser) 
router.delete('/:id', passportJWT.authenticate('jwt', { session: false }), userServices.deleteUser) 
...
-------------------------------------------------------------
src/app.js
-------------------------------------------------------------
...
const authRouter = require('./auth/auth.router')
...
app.use('/api/v1/auth', authRouter)
...
-------------------------------------------------------------
