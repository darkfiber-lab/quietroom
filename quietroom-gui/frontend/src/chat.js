/**
Copyright (C) 2026 darkfiber-lab

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
 * Chat — message rendering, channel tabs, unread counters
 *
 * Channels are keyed as:
 *   "__lobby__"       — the main lobby
 *   "#roomname"       — a joined room
 *   "__dm__username"  — a DM thread with a user
 */

// HTML sanitizer: allow only safe inline tags, strip everything else
function sanitize(html) {
  const allowed = ['b', 'i', 'em', 'strong', 'code', 'pre', 'br',
                   'blockquote', 'u', 's', 'ul', 'ol', 'li', 'a']
  const temp = document.createElement('div')
  temp.textContent = html  // first pass: treat as text (escapes all HTML)

  // Then selectively un-escape safe tags
  // We use a DOMParser approach for safety
  const parser = new DOMParser()
  const doc = parser.parseFromString(html, 'text/html')

  function clean(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      return document.createTextNode(node.textContent)
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return null
    const tag = node.tagName.toLowerCase()
    if (!allowed.includes(tag)) {
      // Replace with span containing children
      const span = document.createElement('span')
      node.childNodes.forEach(child => {
        const c = clean(child)
        if (c) span.appendChild(c)
      })
      return span
    }
    const el = document.createElement(tag)
    // Allow href on <a> if it's http/https only
    if (tag === 'a') {
      const href = node.getAttribute('href') || ''
      if (href.startsWith('http://') || href.startsWith('https://')) {
        el.setAttribute('href', href)
        el.setAttribute('target', '_blank')
        el.setAttribute('rel', 'noopener noreferrer')
      }
    }
    node.childNodes.forEach(child => {
      const c = clean(child)
      if (c) el.appendChild(c)
    })
    return el
  }

  const result = document.createElement('span')
  doc.body.childNodes.forEach(child => {
    const c = clean(child)
    if (c) result.appendChild(c)
  })
  return result.innerHTML
}

// Avatar colour palette — deterministic from username
const AVATAR_COLOURS = [
  ['#00d4ff', '#002a33'],
  ['#b388ff', '#1a0a33'],
  ['#00e676', '#002211'],
  ['#ffd740', '#332b00'],
  ['#ff5252', '#330c0c'],
  ['#40c4ff', '#002233'],
  ['#e040fb', '#270033'],
  ['#69ff47', '#0a2200'],
]
function avatarColour(username) {
  let hash = 0
  for (let i = 0; i < username.length; i++) hash = (hash * 31 + username.charCodeAt(i)) | 0
  return AVATAR_COLOURS[Math.abs(hash) % AVATAR_COLOURS.length]
}

export const Chat = {

  username: '',
  currentChannel: '__lobby__',
  channels: {},         // channelKey → { messages: [], el: HTMLElement, unread: int }
  lastSender: {},       // channelKey → last sender username (for consecutive grouping)
  lastTs: {},           // channelKey → last timestamp string

  init(username) {
    this.username = username
    this.channels = {}
    this.lastSender = {}
    this.lastTs = {}

    // Initialise lobby channel
    this.channels['__lobby__'] = { messages: [], unread: 0 }
    this.currentChannel = '__lobby__'
    this.clearMessages()

    // Wire lobby nav item
    const lobbyItem = document.querySelector('[data-room="__lobby__"]')
    if (lobbyItem) {
      lobbyItem.addEventListener('click', () => this.switchTo('__lobby__'))
    }
  },

  reset() {
      // Clear all channel state
      this.channels = {}
      this.lastSender = {}
      this.lastTs = {}
      this.currentChannel = '__lobby__'
      this.username = ''

      // Clear the message pane
      this.clearMessages()

      // Remove all room nav items except the static lobby item
      const roomList = document.getElementById('room-list')
      Array.from(roomList.querySelectorAll('.nav-item')).forEach(li => {
          if (li.dataset.room !== '__lobby__') li.remove()
      })

      // Remove all DM nav items
      document.getElementById('dm-list').innerHTML = ''

      // Reset lobby nav item to inactive
      const lobbyItem = document.querySelector('[data-room="__lobby__"]')
      if (lobbyItem) lobbyItem.classList.remove('active')

      // Clear any unread badges
      document.querySelectorAll('.unread-badge').forEach(b => {
          b.textContent = ''
          b.classList.add('hidden')
      })
    },

  // ── Channel management ───────────────────────────────────────
  switchTo(channelKey) {
    if (!this.channels[channelKey]) {
      this.channels[channelKey] = { messages: [], unread: 0 }
    }

    this.currentChannel = channelKey
    // Tell the Go/server side about the room switch
    const room = channelKey === '__lobby__' ? '' :
                channelKey.startsWith('__dm__') ? '' : channelKey
    window.go.main.App.SetCurrentRoom(room).catch(console.error)

    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'))
    const navItem = document.querySelector(`[data-room="${channelKey}"]`)
    if (navItem) navItem.classList.add('active')

    // Clear unread
    this.channels[channelKey].unread = 0
    this.updateUnreadBadge(channelKey, 0)

    // Update topbar title
    const title = document.getElementById('topbar-title')
    if (channelKey === '__lobby__') title.textContent = 'Lobby'
    else if (channelKey.startsWith('__dm__')) title.textContent = '@ ' + channelKey.replace('__dm__', '')
    else title.textContent = channelKey

    // Re-render messages for this channel
    this.renderChannel(channelKey)
  },

  addRoom(room, hasPassword = false) {
    if (this.channels[room]) return

    this.channels[room] = { messages: [], unread: 0 }

    const li = document.createElement('li')
    li.className = 'nav-item'
    li.dataset.room = room
    li.innerHTML = `<span class="nav-icon">${hasPassword ? '🔐' : '🔊'}</span>
        <span style="flex:1">${room}</span>
        <span class="leave-btn" title="Leave room" style="color:var(--text-muted);padding:0 4px;cursor:pointer">✕</span>
        <span class="unread-badge hidden" data-room="${room}"></span>`

    li.querySelector('.leave-btn').addEventListener('click', e => {
        e.stopPropagation()
        window.go.main.App.LeaveRoom(room).then(() => {
            li.remove()
            delete this.channels[room]
            this.switchTo('__lobby__')
        }).catch(console.error)
    })
    li.addEventListener('click', () => this.switchTo(room))

    // Add leave button on right-click
    li.addEventListener('contextmenu', e => {
      e.preventDefault()
      if (confirm(`Leave ${room}?`)) {
        window.go.main.App.LeaveRoom(room).then(() => {
          li.remove()
          delete this.channels[room]
          this.switchTo('__lobby__')
        }).catch(console.error)
      }
    })

    document.getElementById('room-list').appendChild(li)
  },

  openDM(partner) {
    const key = `__dm__${partner}`
    if (!this.channels[key]) {
      this.channels[key] = { messages: [], unread: 0 }

      const li = document.createElement('li')
      li.className = 'nav-item'
      li.dataset.room = key
      const [fg] = avatarColour(partner)
      li.innerHTML = `
        <span class="user-avatar" style="width:20px;height:20px;font-size:10px;
          background:transparent;border-color:${fg};color:${fg}">
          ${partner[0].toUpperCase()}
        </span>
        ${partner}
        <span class="unread-badge hidden" data-room="${key}"></span>`
      li.addEventListener('click', () => this.switchTo(key))
      document.getElementById('dm-list').appendChild(li)
    }
    this.switchTo(key)
  },

  // ── Message rendering ────────────────────────────────────────
  renderChannel(channelKey) {
    this.clearMessages()
    this.lastSender[channelKey] = null
    this.lastTs[channelKey] = null

    const msgs = (this.channels[channelKey] || {}).messages || []
    msgs.forEach(m => this._renderOne(m, channelKey, false))
    this.scrollToBottom()
  },

  clearMessages() {
    document.getElementById('messages').innerHTML = ''
  },

  appendMessage(data) {
    // data: { timestamp, username, text, room, isOwn }
    const key = data.room || '__lobby__'
    const msg = { type: 'chat', ...data }

    if (!this.channels[key]) this.channels[key] = { messages: [], unread: 0 }
    this.channels[key].messages.push(msg)

    if (this.currentChannel === key) {
      this._renderOne(msg, key, true)
      this.scrollToBottom()
    } else {
      this.channels[key].unread++
      this.updateUnreadBadge(key, this.channels[key].unread)
    }
  },

  appendDM(data) {
    // data: { timestamp, username, text, partner, isOwn }
    const key = `__dm__${data.partner}`

    if (!this.channels[key]) {
      // Create the DM thread if it doesn't exist yet (incoming DM)
      this.openDM(data.partner)
    }

    const msg = { type: 'dm', ...data }
    this.channels[key].messages.push(msg)

    if (this.currentChannel === key) {
      this._renderOne(msg, key, true)
      this.scrollToBottom()
    } else {
      this.channels[key].unread++
      this.updateUnreadBadge(key, this.channels[key].unread)
    }
  },

  appendSystem(text, room) {
    const key = room || this.currentChannel
    const msg = { type: 'system', text, timestamp: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }

    if (!this.channels[key]) this.channels[key] = { messages: [], unread: 0 }
    this.channels[key].messages.push(msg)

    if (this.currentChannel === key) {
      this._renderOne(msg, key, true)
      this.scrollToBottom()
    }
  },

  appendOwnMessage(text) {
    // Local echo for own messages (before server echo arrives)
    const ts = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    const key = this.currentChannel
    const msg = { type: 'chat', timestamp: ts, username: this.username, text, isOwn: true }
    if (!this.channels[key]) this.channels[key] = { messages: [], unread: 0 }
    this.channels[key].messages.push(msg)
    this._renderOne(msg, key, true)
    this.scrollToBottom()
  },

  _renderOne(msg, channelKey, live) {
    const pane = document.getElementById('messages')

    if (msg.type === 'system') {
      const el = document.createElement('div')
      el.className = 'msg system'
      el.innerHTML = `<div class="msg-avatar"></div>
        <div class="msg-body">
          <span class="msg-text">${this._escapeText(msg.text)}</span>
        </div>`
      pane.appendChild(el)
      return
    }

    const username  = msg.username || 'Unknown'
    const isOwn     = msg.isOwn || username === this.username
    const prevSender = this.lastSender[channelKey]
    const continued  = (prevSender === username)

    this.lastSender[channelKey] = username

    const [fg, bg] = avatarColour(username)
    const initial = username[0].toUpperCase()

    const el = document.createElement('div')
    el.className = 'msg' + (continued ? ' continued' : '')

    const safeText = sanitize(msg.text || '')

    el.innerHTML = `
      <div class="msg-avatar" style="background:${bg};border:1.5px solid ${fg};color:${fg}">
        ${initial}
      </div>
      <div class="msg-body">
        <div class="msg-header">
          <span class="msg-username ${isOwn ? 'own' : ''}">${this._escapeText(username)}</span>
          <span class="msg-ts">${msg.timestamp || ''}</span>
        </div>
        <div class="msg-text">${safeText}</div>
      </div>`

    pane.appendChild(el)
  },

  _escapeText(text) {
    return (text || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  },

  scrollToBottom() {
    const pane = document.getElementById('messages')
    pane.scrollTop = pane.scrollHeight
  },

  updateUnreadBadge(channelKey, count) {
    const badges = document.querySelectorAll(`.unread-badge[data-room="${channelKey}"]`)
    badges.forEach(b => {
      if (count > 0) {
        b.textContent = count > 99 ? '99+' : count
        b.classList.remove('hidden')
      } else {
        b.classList.add('hidden')
      }
    })
  },

  updateUserList(username, action) {
    // Placeholder — could be extended to maintain an online users panel
    console.log(`User ${action}: ${username}`)
  },
}
