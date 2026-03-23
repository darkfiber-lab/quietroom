/**
 * QuietRoom GUI — Main app controller
 * Wires Wails Go bindings to the UI state machine.
 */

import { Chat } from './chat.js'
import { Settings } from './settings.js'
import { FileTransfer } from './filetransfer.js'

// Wails runtime is injected at runtime — safe to reference via window
const go = () => window.go.main.App

export const App = {

  // ── State ──────────────────────────────────────────────────
  connected: false,
  username: '',
  config: null,

  // ── Boot ───────────────────────────────────────────────────
  async init() {
    // Load config from Go
    try {
      this.config = await go().GetConfig()
    } catch (e) {
      console.error('Failed to load config', e)
      this.config = {}
    }

    this.bindConnectScreen()
    this.bindChatScreen()
    this.bindWailsEvents()

    Settings.init(this)
    FileTransfer.init(this)

    this.showScreen('connect')
    Settings.populateConnectScreen(this.config)
  },

  // ── Screen management ───────────────────────────────────────
  showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'))
    const screen = document.getElementById(`screen-${name}`)
    if (screen) screen.classList.add('active')
  },

  // ── Connect screen ──────────────────────────────────────────
  bindConnectScreen() {
    const btnSaveProfile = document.getElementById('btn-save-profile')
    const btnConnect = document.getElementById('btn-connect')
    const btnBrowseCert = document.getElementById('btn-browse-cert')
    const btnSettings = document.getElementById('btn-open-settings')
    const errBox = document.getElementById('connect-error')

    btnConnect.addEventListener('click', () => this.handleConnect())

    document.addEventListener('click', async (e) => {
        if (e.target.id !== 'btn-save-profile' && !e.target.closest('#btn-save-profile')) return
        const host     = document.getElementById('input-host').value.trim()
        const port     = parseInt(document.getElementById('input-port').value) || 37842
        const username = document.getElementById('input-username').value.trim()
        const cert     = document.getElementById('input-cert').value.trim() || 'chat_public.pem'
        const errBox   = document.getElementById('connect-error')

        if (!host || !username) {
            errBox.textContent = 'Host and username are required to save a profile.'
            errBox.classList.remove('hidden')
            return
        }
        
        const name = `${username}@${host}`
        const newProfile = {
            name:      name.trim(),
            host:      host,
            port:      port,
            username:  username,
            cert_file: cert,
        }

        const config = { ...this.config }
        const profiles = config.profiles || []
        profiles.push(newProfile)
        config.profiles = profiles

        try {
            await go().SaveConfig(config)
            this.config = config
            Settings.populateConnectScreen(config)
            errBox.classList.add('hidden')
            errBox.textContent = '✓ Profile saved'
            errBox.classList.remove('hidden')
            errBox.style.background = 'rgba(0, 230, 118, 0.12)'
            errBox.style.borderColor = 'rgba(0, 230, 118, 0.3)'
            errBox.style.color = 'var(--green)'
            setTimeout(() => errBox.classList.add('hidden'), 2000)
        } catch (e) {
            errBox.textContent = 'Failed to save profile: ' + e
            errBox.classList.remove('hidden')
        }
    })

    document.getElementById('input-host').addEventListener('keydown', e => {
      if (e.key === 'Enter') this.handleConnect()
    })
    document.getElementById('input-username').addEventListener('keydown', e => {
      if (e.key === 'Enter') this.handleConnect()
    })

    btnBrowseCert.addEventListener('click', async () => {
      try {
        const path = await go().PickFile()
        if (path) document.getElementById('input-cert').value = path
      } catch (e) {
        console.error(e)
      }
    })

    btnSettings.addEventListener('click', () => {
      Settings.openModal(this.config)
    })

    document.getElementById('profile-select').addEventListener('change', e => {
        const idx = parseInt(e.target.value)
        const profiles = this.config && (this.config.profiles || this.config.Profiles) || []
        if (profiles[idx]) {
            const p = profiles[idx]
            document.getElementById('input-host').value     = p.host     || p.Host     || ''
            document.getElementById('input-port').value     = p.port     || p.Port     || 37842
            document.getElementById('input-username').value = p.username || p.Username || ''
            document.getElementById('input-cert').value     = p.cert_file || p.CertFile || ''
        }
    })
  },

  async handleConnect() {
    const host     = document.getElementById('input-host').value.trim()
    const port     = parseInt(document.getElementById('input-port').value)
    const username = document.getElementById('input-username').value.trim()
    const cert     = document.getElementById('input-cert').value.trim() || 'chat_public.pem'
    const errBox   = document.getElementById('connect-error')
    const btn      = document.getElementById('btn-connect')

    errBox.classList.add('hidden')

    if (!host || !username) {
      errBox.textContent = 'Host and username are required.'
      errBox.classList.remove('hidden')
      return
    }

    btn.disabled = true
    btn.textContent = 'Connecting…'

    try {
      await go().ConnectCustom(host, port || 37842, cert, username)
      // Success is handled by the 'connected' Wails event
    } catch (e) {
      errBox.textContent = e.toString()
      errBox.classList.remove('hidden')
      btn.disabled = false
      btn.textContent = 'Connect'
    }
  },

  // ── Chat screen ─────────────────────────────────────────────
  bindChatScreen() {
    // Send on Enter
    const input = document.getElementById('message-input')
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        this.sendCurrentInput()
      }
    })

    document.getElementById('btn-send').addEventListener('click', () => {
      this.sendCurrentInput()
    })

    document.getElementById('btn-disconnect').addEventListener('click', () => {
      this.handleDisconnect()
    })

    // Attach file
    document.getElementById('btn-attach').addEventListener('click', async () => {
      await FileTransfer.pickAndInitiate(this)
    })

    // Join room modal
    document.getElementById('btn-join-room').addEventListener('click', () => {
      this.openModal('modal-join-room')
      this._roomSuggestions = []
      // Fetch rooms on open
      go().RequestRoomList().catch(console.error)
      this._awaitingRoomList = true
      this._roomListForSuggestions = true
      setTimeout(() => document.getElementById('join-room-name').focus(), 50)
    })

    document.getElementById('btn-confirm-join').addEventListener('click', async () => {
      let room = document.getElementById('join-room-name').value.trim()
      if (!room.startsWith('#')) room = '#' + room
      const pw   = document.getElementById('join-room-password').value.trim()
      if (!room) return
      try {
        await go().JoinRoom(room, pw)
        Chat.addRoom(room, pw.length > 0)
        Chat.switchTo(room)
        this.closeModal('modal-join-room')
        document.getElementById('join-room-name').value = ''
        document.getElementById('join-room-password').value = ''
      } catch (e) {
        Chat.appendSystem(`Error joining room: ${e}`)
      }
    })

    // New DM modal
    document.getElementById('btn-new-dm').addEventListener('click', () => {
      this.openModal('modal-new-dm')
      this._userSuggestions = []
      // Fetch users on open
      go().RequestUserList().catch(console.error)
      this._awaitingUserList = true
      this._userListForSuggestions = true
      setTimeout(() => document.getElementById('dm-target-username').focus(), 50)
    })

    document.getElementById('btn-confirm-dm').addEventListener('click', () => {
      const user = document.getElementById('dm-target-username').value.trim()
      if (!user) return
      Chat.openDM(user)
      this.closeModal('modal-new-dm')
      document.getElementById('dm-target-username').value = ''
    })

    document.getElementById('btn-open-settings').addEventListener('click', () => {
      Settings.openModal(this.config)
    })
    // Room name autocomplete filtering
    document.getElementById('join-room-name').addEventListener('input', () => {
      if (this._roomSuggestions && this._roomSuggestions.length > 0) {
        this._populateRoomSuggestions(this._roomSuggestions)
      }
    })
    document.getElementById('join-room-name').addEventListener('blur', () => {
      setTimeout(() => {
        document.getElementById('join-room-suggestions').classList.add('hidden')
      }, 150)
    })
    document.getElementById('join-room-name').addEventListener('focus', () => {
      if (this._roomSuggestions && this._roomSuggestions.length > 0) {
        this._populateRoomSuggestions(this._roomSuggestions)
      }
    })

    // Username autocomplete filtering
    document.getElementById('dm-target-username').addEventListener('input', () => {
      if (this._userSuggestions && this._userSuggestions.length > 0) {
        this._populateUserSuggestions(this._userSuggestions)
      }
    })
    document.getElementById('dm-target-username').addEventListener('blur', () => {
      setTimeout(() => {
        document.getElementById('dm-suggestions').classList.add('hidden')
      }, 150)
    })
    document.getElementById('dm-target-username').addEventListener('focus', () => {
      if (this._userSuggestions && this._userSuggestions.length > 0) {
        this._populateUserSuggestions(this._userSuggestions)
      }
    })
  },

  sendCurrentInput() {
    const input = document.getElementById('message-input')
    const text  = input.value.trim()
    if (!text) return

    input.value = ''

    const currentChannel = Chat.currentChannel

    // DM context
    if (currentChannel.startsWith('__dm__')) {
      const partner = currentChannel.replace('__dm__', '')
      go().SendDM(partner, text).catch(e => Chat.appendSystem(`Error: ${e}`))
      // Chat.appendOwnMessage(text)
      return
    }

    // Raw command
    if (text.startsWith('/')) {
      go().SendCommand(text).catch(e => Chat.appendSystem(`Error: ${e}`))
      return
    }

    // Lobby or room message
    go().SendMessage(text).catch(e => Chat.appendSystem(`Error: ${e}`))
    // Chat.appendOwnMessage(text)
  },

  handleDisconnect() {
    go().Disconnect()
  },

  // ── Wails events ────────────────────────────────────────────
  bindWailsEvents() {
    const runtime = window.runtime

    runtime.EventsOn('connected', data => {
      this.connected = true
      this.username = data.username
      document.getElementById('sidebar-username').textContent = data.username
      document.getElementById('sidebar-avatar').textContent = data.username[0].toUpperCase()
      document.getElementById('status-dot').className = 'status-dot connected'
      Chat.init(this.username)
      this.showScreen('chat')
      Chat.appendSystem(`Connected to ${data.address} as ${data.username}`)
    })

    runtime.EventsOn('disconnected', () => {
        this.connected = false
        document.getElementById('status-dot').className = 'status-dot'
        Chat.appendSystem('Disconnected from server.')
        setTimeout(() => {
            const btn = document.getElementById('btn-connect')
            btn.disabled = false
            btn.textContent = 'Connect'

            // Full UI reset — wipe all channel state so stale rooms/DMs
            // don't carry over into the next session
            Chat.reset()

            this.showScreen('connect')
        }, 2000)
    })

    runtime.EventsOn('error', data => {
      Chat.appendSystem(`⚠ ${data.message}`)
    })

    runtime.EventsOn('message', data => {
      Chat.appendMessage(data)
    })

    runtime.EventsOn('dm', data => {
      Chat.appendDM(data)
    })

    runtime.EventsOn('system_message', data => {
      const text = data.text || ''

      // Room list response — lines starting with # are rooms
      if (this._awaitingRoomList && (text.includes('#') || text.toLowerCase().includes('room'))) {
        this._awaitingRoomList = false
        const rooms = text.split('\n')
          .map(l => l.trim())
          .filter(l => l.startsWith('#'))
          .map(l => l.split(' ')[0])  // strip member count
        if (this._roomListForSuggestions) {
          this._roomListForSuggestions = false
          this._roomSuggestions = rooms
          this._populateRoomSuggestions(rooms)
        } else {
          this.showRoomListModal(rooms)
        }
        return
      }

      // User list response
      if (this._awaitingUserList) {
        if (text.toLowerCase().includes('online users')) {
          this._awaitingUserList = false
          const colonIdx = text.indexOf(':')
          if (colonIdx !== -1) {
            const users = text.substring(colonIdx + 1)
              .trim()
              .split(/\s+|\n\s*/)
              .filter(Boolean)
            if (users.length > 0) {
              if (this._userListForSuggestions) {
                this._userListForSuggestions = false
                this._userSuggestions = users.filter(u => u !== this.username)
                this._populateUserSuggestions(this._userSuggestions)
              } else {
                this.showUserListModal(users)
              }
              return
            }
          }
        }
      }

    if (this._awaitingMemberList) {
        if (text.toLowerCase().includes('members of')) {
            this._awaitingMemberList = false
            const colonIdx = text.indexOf(':')
            if (colonIdx !== -1) {
                const members = text.substring(colonIdx + 1)
                  .trim()
                  .split(/\s+|\n\s*/)
                  .filter(Boolean)
                this.showMemberListModal(members, this._memberListContext)
                return
            }
        }
        // Access denied response
        if (text.includes('access denied') || text.includes('not found')) {
            this._awaitingMemberList = false
            Chat.appendSystem(text)
            return
        }
    }

      Chat.appendSystem(text)
    })

    runtime.EventsOn('user_joined', data => {
      Chat.appendSystem(`${data.username} joined the chat`)
      Chat.updateUserList(data.username, 'add')
    })

    runtime.EventsOn('user_left', data => {
      Chat.appendSystem(`${data.username} left the chat`)
      Chat.updateUserList(data.username, 'remove')
    })

    runtime.EventsOn('room_joined', data => {
      if (data.username !== this.username) {
        Chat.appendSystem(`${data.username} joined ${data.room}`, data.room)
      }
    })

    runtime.EventsOn('room_left', data => {
      Chat.appendSystem(`${data.username} left ${data.room}`, data.room)
    })

    runtime.EventsOn('file_request', data => {
      FileTransfer.showRequest(data)
    })

    runtime.EventsOn('file_progress', data => {
      FileTransfer.updateSendProgress(data)
    })

    runtime.EventsOn('file_start', data => {
      FileTransfer.startReceive(data)
    })

    runtime.EventsOn('file_receive_progress', data => {
      FileTransfer.updateReceiveProgress(data)
    })

    runtime.EventsOn('file_complete', data => {
      FileTransfer.completeReceive(data)
    })
  },

  // ── Modal helpers ────────────────────────────────────────────
  openModal(id) {
    document.getElementById(id).classList.remove('hidden')
  },

  closeModal(id) {
    document.getElementById(id).classList.add('hidden')
  },

  // ── Convenience proxies used by inline onclick handlers ─────
  listRooms() {
    go().RequestRoomList().catch(console.error)
    this._awaitingRoomList = true
  },

  listUsers() {
      go().RequestUserList().catch(console.error)
      this._awaitingUserList = true
  },

  listMembers() {
      const channel = Chat.currentChannel
      const target = channel === '__lobby__' ? 'lobby' :
                    channel.startsWith('__dm__') ? 'lobby' : channel
      go().RequestMemberList(target).catch(console.error)
      this._awaitingMemberList = true
      this._memberListContext = target
  },
  showRoomListModal(rooms) {
    const list = document.getElementById('room-list-items')
    list.innerHTML = ''
    if (rooms.length === 0) {
      list.innerHTML = '<li style="color:var(--text-muted);font-size:13px">No rooms available</li>'
    } else {
      rooms.forEach(room => {
        const roomName = room.split(' ')[0]
        const li = document.createElement('li')
        li.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:var(--bg-input);border-radius:6px'
        li.innerHTML = `<span style="font-size:13px">${room}</span>
          <button class="btn btn-primary btn-sm">Join</button>`
        li.querySelector('button').addEventListener('click', () => {
          go().JoinRoom(roomName, '').then(() => {
            Chat.addRoom(roomName)
            Chat.switchTo(roomName)
            this.closeModal('modal-room-list')
          }).catch(e => Chat.appendSystem(`Error joining ${room}: ${e}`))
        })
        list.appendChild(li)
      })
    }
    this.openModal('modal-room-list')
  },

  showUserListModal(users) {
    const context = this._userListContext || '__lobby__'
    const title = context === '__lobby__' ? 'Lobby Users' :
                  context.startsWith('#') ? `Users in ${context}` : 'Online Users'
    document.querySelector('#modal-user-list h3').textContent = title

    const list = document.getElementById('user-list-items')
    list.innerHTML = ''
    users.forEach(user => {
        if (user === this.username) return
        const li = document.createElement('li')
        li.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:var(--bg-input);border-radius:6px'
        li.innerHTML = `<span style="font-size:13px">${user}</span>
            <button class="btn btn-primary btn-sm">DM</button>`
        li.querySelector('button').addEventListener('click', () => {
            Chat.openDM(user)
            this.closeModal('modal-user-list')
        })
        list.appendChild(li)
    })
    this.openModal('modal-user-list')
  },

  showMemberListModal(members, context) {
      const title = context === 'lobby' ? 'Lobby Members' : `Members of ${context}`
      document.querySelector('#modal-user-list h3').textContent = title

      const list = document.getElementById('user-list-items')
      list.innerHTML = ''
      if (members.length === 0) {
          list.innerHTML = '<li style="color:var(--text-muted);font-size:13px">No members</li>'
      } else {
          members.forEach(user => {
              if (user === this.username) return
              const li = document.createElement('li')
              li.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:var(--bg-input);border-radius:6px'
              li.innerHTML = `<span style="font-size:13px">${user}</span>
                  <button class="btn btn-primary btn-sm">DM</button>`
              li.querySelector('button').addEventListener('click', () => {
                  Chat.openDM(user)
                  this.closeModal('modal-user-list')
              })
              list.appendChild(li)
          })
      }
      this.openModal('modal-user-list')
  },

    _populateRoomSuggestions(rooms) {
    const input = document.getElementById('join-room-name')
    const list  = document.getElementById('join-room-suggestions')
    const query = input.value.trim().toLowerCase()

    const filtered = query
      ? rooms.filter(r => r.toLowerCase().includes(query))
      : rooms

    list.innerHTML = ''
    if (filtered.length === 0) {
      list.classList.add('hidden')
      return
    }

    filtered.forEach(room => {
      const li = document.createElement('li')
      li.textContent = room
      li.addEventListener('mousedown', e => {
        e.preventDefault()
        input.value = room
        list.classList.add('hidden')
        document.getElementById('join-room-password').focus()
      })
      list.appendChild(li)
    })
    list.classList.remove('hidden')
  },

  _populateUserSuggestions(users) {
    const input = document.getElementById('dm-target-username')
    const list  = document.getElementById('dm-suggestions')
    const query = input.value.trim().toLowerCase()

    const filtered = query
      ? users.filter(u => u.toLowerCase().includes(query))
      : users

    list.innerHTML = ''
    if (filtered.length === 0) {
      list.classList.add('hidden')
      return
    }

    filtered.forEach(user => {
      const li = document.createElement('li')
      li.textContent = user
      li.addEventListener('mousedown', e => {
        e.preventDefault()
        input.value = user
        list.classList.add('hidden')
      })
      list.appendChild(li)
    })
    list.classList.remove('hidden')
  },

}
