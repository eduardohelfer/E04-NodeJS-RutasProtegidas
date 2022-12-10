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