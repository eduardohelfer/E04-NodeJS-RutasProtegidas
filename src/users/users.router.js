const router = require('express').Router()

const userServices = require('./users.services')
const passportJWT = require('../middleware/auth.middleware')

router.get("/", userServices.getAllUsers) //? /api/v1/users
router.post("/", userServices.postUser) //? /api/v1/users

router.get("/:id", userServices.getUserById) //? /api/v1/users/:id
router.patch("/:id", passportJWT.authenticate('jwt', { session: false }), userServices.patchUser)
router.delete("/:id", passportJWT.authenticate('jwt', { session: false }), userServices.deleteUser)

module.exports = router