// ** JWT import
import jwt from 'jsonwebtoken'

// ** Mock Adapter
import mock from 'src/@fake-db/mock'

// ** Default AuthConfig
import defaultAuthConfig from 'src/configs/auth'

// ** Types
import { UserDataType } from 'src/context/types'

const users: UserDataType[] = [
  {
    id: 1,
    role: 'admin',
    password: 'admin',
    fullName: 'John Doe',
    username: 'johndoe',
    email: 'admin@materialize.com'
  },
  {
    id: 2,
    role: 'client',
    password: 'client',
    fullName: 'Jane Doe',
    username: 'janedoe',
    email: 'client@materialize.com'
  }
]

interface JWTConfig {
  secret: string | undefined
  expirationTime: string | undefined
  refreshTokenSecret: string | undefined
}

// Asegurarnos de que jwtConfig tenga los tipos correctos
const jwtConfig: JWTConfig = {
  secret: process.env.NEXT_PUBLIC_JWT_SECRET,
  expirationTime: process.env.NEXT_PUBLIC_JWT_EXPIRATION,
  refreshTokenSecret: process.env.NEXT_PUBLIC_JWT_REFRESH_TOKEN_SECRET
}

type ResponseType = [number, { [key: string]: any }]

// Función helper para firmar tokens de forma segura
const signToken = (payload: any, secret: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    jwt.sign(
      payload,
      secret,
      {
        algorithm: 'HS256',
        expiresIn: '1h'
      },
      (err, token) => {
        if (err) {
          reject(err)
        } else if (token) {
          resolve(token)
        } else {
          reject(new Error('Token generation failed'))
        }
      }
    )
  })
}

mock.onPost('/jwt/login').reply(async (request) => {
  const { email, password } = JSON.parse(request.data)

  try {
    const user = users.find(u => u.email === email && u.password === password)
    console.log('Login attempt:', {
      email,
      foundUser: !!user
    })

    if (user) {
      try {
        const secret = (jwtConfig.secret || 'secret-key').toString().trim()
        const payload = { id: user.id }

        const accessToken = await signToken(payload, secret)
        console.log('Token generated successfully')

        const response = {
          accessToken,
          userData: { ...user, password: undefined }
        }

        return [200, response]
      } catch (err) {
        console.error('Token generation failed:', err)
        return [400, {
          error: {
            email: ['Authentication error occurred']
          }
        }]
      }
    }

    return [400, {
      error: {
        email: ['Email or Password is Invalid']
      }
    }]
  } catch (err) {
    console.error('Login error:', err)
    return [500, {
      error: {
        email: ['An unexpected error occurred']
      }
    }]
  }
})

mock.onPost('/jwt/register').reply(request => {
  if (request.data.length > 0) {
    const { email, password, username } = JSON.parse(request.data)
    const isEmailAlreadyInUse = users.find(user => user.email === email)
    const isUsernameAlreadyInUse = users.find(user => user.username === username)
    const error = {
      email: isEmailAlreadyInUse ? 'This email is already in use.' : null,
      username: isUsernameAlreadyInUse ? 'This username is already in use.' : null
    }

    if (!error.username && !error.email) {
      const { length } = users
      let lastIndex = 0
      if (length) {
        lastIndex = users[length - 1].id
      }
      const userData = {
        id: lastIndex + 1,
        email,
        password,
        username,
        avatar: null,
        fullName: '',
        role: 'admin'
      }

      users.push(userData)

      const accessToken = jwt.sign(
        { id: userData.id },
        jwtConfig.secret || 'secret-key',
        { expiresIn: Number(jwtConfig.expirationTime) || '1h' }
      )

      const user = { ...userData }
      delete user.password

      const response = { accessToken }

      return [200, response]
    }

    return [200, { error }]
  } else {
    return [401, { error: 'Invalid Data' }]
  }
})

mock.onGet('/auth/me').reply((config) => {
  return new Promise((resolve) => {
    try {
      // @ts-ignore
      const token = config.headers.Authorization as string
      const secret = (jwtConfig.secret || 'secret-key').toString().trim()

      jwt.verify(token, secret, (err, decoded) => {
        if (err) {
          resolve([401, { error: { error: 'Invalid Token' } }])
          return
        }

        // @ts-ignore
        const userId = decoded?.id
        const userData = users.find((u: UserDataType) => u.id === userId)

        if (userData) {
          const userDataWithoutPassword = { ...userData, password: undefined }
          resolve([200, { userData: userDataWithoutPassword }])
        } else {
          resolve([401, { error: { error: 'Invalid User' } }])
        }
      })
    } catch (err) {
      console.error('Token verification error:', err)
      resolve([401, { error: { error: 'Invalid Token' } }])
    }
  })
})
