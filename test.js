import test from 'ava'
import jose from 'node-jose'
import jwt from 'jsonwebtoken'

process.env.MOUNT = '/api/v1'

const safeApi = require('./index')

test.before(async t => {
  const key = await jose.JWK.createKey('EC', 'P-384')
  t.context.publicKey = key.toPEM(false)
  t.context.privateKey = key.toPEM(true)
})

test('errorIfNoAuthorizationHeader guarda el encabezado Authorization en req y llama next si está el encabezado Authorization', t => {
  var token = 'encabezado authorization'
  var req = {
    get () {
      return token
    }
  }
  var res = null
  function next () {
    t.is(req.token, token)
  }
  safeApi.errorIfNoAuthorizationHeader(req, res, next)
})

test('errorIfNoAuthorizationHeader devuelve error si falta el encabezado Authorization', t => {
  var req = {
    get () {}
  }
  var res = {
    authError (code) {
      t.is(code, 'AuthorizationRequired')
    }
  }
  var next = t.fail

  safeApi.errorIfNoAuthorizationHeader(req, res, next)
})

test('insecure llama next(route) y establece req.safeApiJwt.iss si el header es insecure', t => {
  var req = {
    token: 'insecure mi-uuid'
  }

  var res = null
  function next (param) {
    t.is(param, 'route')
    t.is(req.safeApiJwt.iss, 'mi-uuid')
    t.falsy(req.token)
  }
  safeApi.insecure(req, res, next)
})

test('insecure llama next si el header es no insecure', t => {
  var req = {
    token: 'no insecure mi-uuid'
  }

  var res = null
  function next (param) {
    t.falsy(param)
    t.falsy(req.safeApiJwt.iss)
    t.assert(req.token)
  }
  safeApi.insecure(req, res, next)
})

test('parseJWT Lee el JWT', t => {
  var req = {
    token: jwt.sign({
      ok: true
    }, t.context.privateKey, {
      algorithm: 'ES384'
    })
  }
  var res = null
  function next () {
    t.assert(req.safeApiJwt)
  }

  safeApi.parseJWT(req, res, next)
})

test('checkTimes llama a next si epoch está entre iat y exp', t => {
  const epoch = Math.floor(Date.now() / 1000)
  var req = {
    jwt: {
      iat: epoch - 10,
      exp: epoch + 10
    }
  }
  safeApi.checkTimes(req, null, t.pass)
})
test('checkTimes devuelve error ExpiredToken si epoch es posterior a exp', t => {
  const epoch = Math.floor(Date.now() / 1000)
  var req = {
    jwt: {
      iat: epoch - 20,
      exp: epoch - 10
    }
  }
  var res = {
    authError (code) {
      t.is(code, 'ExpiredToken')
    }
  }
  safeApi.checkTimes(req, res, t.fail)
})
test('checkTimes devuelve error TimeError si iat es posterior a epoch', t => {
  const epoch = Math.floor(Date.now() / 1000)
  var req = {
    jwt: {
      iat: epoch + 10,
      exp: epoch + 20
    }
  }
  var res = {
    authError (code) {
      t.is(code, 'TimeError')
    }
  }
  safeApi.checkTimes(req, res, t.fail)
})

test('hashRequest guarda en req.sub el hash de la petición', t => {
  safeApi.config.mount = '/api/v1'
  var req = {
    body: 'body',
    hostname: 'humanbotnet.localhost.hacknlove.org',
    method: 'POST',
    originalUrl: '/algo',
    protocol: 'https'
  }

  var res = null

  function next () {
    t.is(req.sub, 'biHZrFP+VKToJ9V4Gk4lX0D6tt7YZUWx0P/zFeT22WE=')
  }

  safeApi.hashRequest(req, res, next)
})
test('checkSub llama a next si req.sub es igual a req.safeApiJwt.sub', t => {
  var req = {
    sub: 'IGUAL',
    jwt: {
      sub: 'IGUAL'
    }
  }

  var res = null

  var next = t.pass

  safeApi.checkSub(req, res, next)
})
test('checkSub devuelve InvalidSignature si req.sub no es igual a req.safeApiJwt.sub', t => {
  var req = {
    sub: 'Diferente',
    jwt: {
      sub: 'Distinto'
    }
  }

  var res = {
    authError (code) {
      t.is(code, 'InvalidSignature')
    }
  }

  var next = t.fail

  safeApi.checkSub(req, res, next)
})

test('errorIfNotExistsKey llama a next si existe publicKey', t => {
  safeApi.errorIfNotExistsKey({
    publicKey: true
  }, null, t.pass)
})
test('errorIfNotExistsKey devuelve error KeyNotFound si no existe publicKey', t => {
  safeApi.errorIfNotExistsKey({}, {
    authError (code) {
      t.is(code, 'KeyNotFound')
    }
  }, t.fail)
})

test.cb('verifyJwt llama a next si el token está correctamente firmado', t => {
  var req = {
    token: jwt.sign({
      ok: true
    }, t.context.privateKey, {
      algorithm: 'ES384'
    }),
    publicKey: t.context.publicKey
  }
  safeApi.verifyJwt(req, null, () => {
    t.pass()
    t.end()
  })
})

test.cb('verifyJwt devuelve error InvalidSignature el token no está correctamente firmado', t => {
  var req = {
    token: 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjOWFkNTYwYy01ODMzLTQxN2UtYTc2ZC0yYjMzMWJmNzUxYzgiLCJzdWIiOiJYanQ0eUJ5VnN3Ly9YbmRFOWRuMEp4YVdRSHIxT25zUXVnckhvWlBWUGxzPSIsImlhdCI6MTU2MzAxMTc4MywiZXhwIjoxNTYzMDExOTAzfQ.jHDHqjOkKgNsxGPqPAU77A8KmknBzwE5dECXC0WK2QGh_wYIQDivTBmQXtc_tkai9CcWYW4kwIfV-pDkMPFta591pgr0QXiwu8cA2QaIkpyirMy609meQ45TXw_sx2Pt',
    publicKey: t.context.publicKey
  }
  safeApi.verifyJwt(req, {
    authError (code) {
      t.is(code, 'InvalidSignature')
      t.end()
    }
  }, t.fail)
})
