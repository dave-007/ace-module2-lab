/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(part => parseInt(part, 10))
  if (parts.length !== 4 || parts.some(isNaN)) {
    return true
  }
  const [a, b, c] = parts

  if (a === 0) return true
  if (a === 10) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true

  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const normalized = ip.toLowerCase().trim()

  if (normalized === '::1' || normalized === '::') return true

  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.substring(7)
    if (net.isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part)
    }
    return true
  }

  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
  if (/^fe[89ab]/i.test(normalized)) return true
  if (normalized.startsWith('100:')) return true
  if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return true

  return false
}

function isSafeUrl (urlStr: string): boolean {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlStr)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  const rawHostname = parsedUrl.hostname.toLowerCase()
  if (!rawHostname) {
    return false
  }

  const hostname = rawHostname.replace(/^\[|\]$/g, '')

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.arpa')
  ) {
    return false
  }

  const ipType = net.isIP(hostname)
  if (ipType === 4) {
    if (isPrivateIPv4(hostname)) {
      return false
    }
  } else if (ipType === 6) {
    if (isPrivateIPv6(hostname)) {
      return false
    }
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string' || !isSafeUrl(url)) {
        res.status(400)
        next(new Error('Invalid or disallowed image URL'))
        return
      }
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
