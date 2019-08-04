const jwt = require('jsonwebtoken')
const crypto = require('crypto')

var config = {
  mount: '',
  getPublicKey (req, res, next) {
    res.authError('getPublicKeyNotSet')
  },
  allowedAlgorithms: [
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'ES256',
    'ES384',
    'ES512'
  ]
}

function authError (req, res, next) {
  res.authError = res.authError || function (error, info) { res.json({ error, info }) }
  next()
}

function insecure (req, res, next) {
  if (req.token.match(/^insecure /)) {
    req.safeApiJwt = {
      iss: req.token.substr(9)
    }
    delete req.token
    return next('route')
  }
  next()
}

function errorIfNoAuthorizationHeader (req, res, next) {
  req.token = req.get('Authorization')
  if (!req.token) {
    return res.authError('AuthorizationRequired')
  }
  next()
}

function parseJWT (req, res, next) {
  req.safeApiJwt = jwt.decode(req.token, {
    complete: true
  })
  if (req.safeApiJwt === null) {
    res.authError('InvalidToken', req.token)
  }
  next()
}

function checkAlgorithm (req, res, next) {
  if (config.allowedAlgorithms.includes(req.safeApiJwt.header.alg)) {
    req.safeApiJwt = req.safeApiJwt.payload
    return next()
  }
  res.authError('algorithmNotAllowed')
}

function checkTimes (req, res, next) {
  const epoch = Math.floor(Date.now() / 1000)
  if (req.safeApiJwt.exp < epoch) {
    return res.authError('ExpiredToken')
  }
  if (epoch < req.safeApiJwt.iat) {
    return res.authError('TimeError')
  }

  next()
}

function hashRequest (req, res, next) {
  const hash = crypto.createHash('sha256')

  hash.update(JSON.stringify({
    body: req.body,
    hostname: req.hostname,
    method: req.method,
    originalUrl: config.mount + req.originalUrl,
    protocol: req.protocol
  }))
  req.sub = hash.digest('base64')
  next()
}

function checkSub (req, res, next) {
  if (req.sub === req.safeApiJwt.sub) {
    return next()
  }
  return res.authError('InvalidSignature', 'hash')
}

async function getPublicKey (req, res, next) {
  config.getPublicKey(req, res, next)
}

function errorIfNotExistsKey (req, res, next) {
  if (!req.publicKey) {
    return res.authError('KeyNotFound')
  }
  next()
}

function verifyJwt (req, res, next) {
  jwt.verify(req.token, req.publicKey, {
    ignoreExpiration: true
  }, e => {
    if (e) {
      return res.authError('InvalidSignature', 'token')
    }
    next()
  })
}

function clean (req, res, next) {
  delete req.token
  next()
}

function checkToken (token, request) {
  return new Promise((resolve, reject) => {
    const steps = [
      parseJWT,
      checkTimes,
      hashRequest,
      checkSub,
      getPublicKey,
      errorIfNotExistsKey,
      verifyJwt,
      (req, res, next) => {
        resolve(req.safeApiJwt.iss)
      }
    ]
    const req = {
      body: {},
      ...request,
      token
    }
    const res = {
      authError: reject
    }
    function next (params) {
      const step = steps.unshift()
      step(req, res, next)
    }
  })

}

module.exports = [
  authError,
  errorIfNoAuthorizationHeader,
  parseJWT,
  checkAlgorithm,
  checkTimes,
  hashRequest,
  checkSub,
  getPublicKey,
  errorIfNotExistsKey,
  verifyJwt,
  clean
]

module.exports.config = config
module.exports.checkToken = checkToken

if (process.env.NODE_ENV === 'test') {
  module.exports.checkSub = checkSub
  module.exports.checkTimes = checkTimes
  module.exports.checkToken = checkToken
  module.exports.clean = clean
  module.exports.errorIfNoAuthorizationHeader = errorIfNoAuthorizationHeader
  module.exports.errorIfNotExistsKey = errorIfNotExistsKey
  module.exports.getPublicKey = getPublicKey
  module.exports.hashRequest = hashRequest
  module.exports.insecure = insecure
  module.exports.parseJWT = parseJWT
  module.exports.verifyJwt = verifyJwt
}

if (process.env.NODE_ENV === 'developing') {
  module.exports.splice(1, 0, insecure)
}
