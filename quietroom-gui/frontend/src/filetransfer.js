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
 * 
 * FileTransfer — handles the UI for both sending and receiving files
 */

import { Chat } from './chat.js'

let _app = null
let _pendingTransferID = null
let _pendingRecipient = null

export const FileTransfer = {

  init(app) {
    _app = app

    document.getElementById('btn-accept-file').addEventListener('click', async () => {
      if (!_pendingTransferID) return
      try {
        await window.go.main.App.AcceptFileTransfer(_pendingTransferID)
        app.closeModal('modal-file-request')
        Chat.appendSystem(`Accepted file transfer ${_pendingTransferID}`)
      } catch (e) {
        Chat.appendSystem(`Error accepting transfer: ${e}`)
      }
    })

    document.getElementById('btn-decline-file').addEventListener('click', async () => {
      if (!_pendingTransferID) return
      try {
        await window.go.main.App.DeclineFileTransfer(_pendingTransferID)
        app.closeModal('modal-file-request')
        Chat.appendSystem(`Declined file transfer from ${_pendingTransferID}`)
      } catch (e) {
        Chat.appendSystem(`Error declining transfer: ${e}`)
      }
      _pendingTransferID = null
    })
  },

  async pickAndInitiate(app) {
    // Determine recipient from current channel
    const channel = Chat.currentChannel
    let recipient = ''

    if (channel.startsWith('__dm__')) {
      recipient = channel.replace('__dm__', '')
    } else {
      // Prompt for recipient if not in DM
      recipient = prompt('Send file to (username):')
      if (!recipient) return
    }

    try {
      const path = await window.go.main.App.PickFile()
      if (!path) return
      _pendingRecipient = recipient
      await window.go.main.App.InitiateFileTransfer(recipient, path)
      Chat.appendSystem(`File transfer request sent to ${recipient}. Waiting for acceptance…`)
    } catch (e) {
      Chat.appendSystem(`File transfer error: ${e}`)
    }
  },

  showRequest(data) {
    _pendingTransferID = data.transferID
    _app.openModal('modal-file-request')

    document.getElementById('file-request-details').innerHTML = `
      <div><strong>From:</strong> ${_escHtml(data.senderName)}</div>
      <div><strong>File:</strong> ${_escHtml(data.filename)}</div>
      <div class="file-request-hash"><strong>SHA-256:</strong> ${_escHtml(data.expectedHash)}</div>
      <div><strong>Transfer ID:</strong> ${_escHtml(data.transferID)}</div>`
  },

  updateSendProgress(data) {
    const bar   = document.getElementById('transfer-bar')
    const fill  = document.getElementById('transfer-fill')
    const label = document.getElementById('transfer-label')
    const pct   = document.getElementById('transfer-pct')

    if (data.done) {
      bar.classList.add('hidden')
      Chat.appendSystem(
        `✓ File sent: ${data.filename} — SHA-256: ${data.hash}`
      )
      return
    }

    bar.classList.remove('hidden')
    label.textContent = `Sending ${data.filename}…`
    const p = Math.round(data.percent || 0)
    fill.style.width = `${p}%`
    pct.textContent = `${p}%`
  },

  startReceive(data) {
    const bar   = document.getElementById('transfer-bar')
    const label = document.getElementById('transfer-label')
    const fill  = document.getElementById('transfer-fill')
    const pct   = document.getElementById('transfer-pct')

    bar.classList.remove('hidden')
    label.textContent = `Receiving ${data.filename}…`
    fill.style.width = '0%'
    pct.textContent = '0%'

    Chat.appendSystem(
      `Incoming file: ${data.filename} (${_formatBytes(data.filesize)})` +
      (data.expectedHash ? ` — Expected SHA-256: ${data.expectedHash}` : '')
    )
  },

  updateReceiveProgress(data) {
    const fill = document.getElementById('transfer-fill')
    const pct  = document.getElementById('transfer-pct')
    const p = Math.round(data.percent || 0)
    fill.style.width = `${p}%`
    pct.textContent = `${p}%`
  },

  completeReceive(data) {
    const bar = document.getElementById('transfer-bar')
    bar.classList.add('hidden')

    if (data.hashMatch) {
      Chat.appendSystem(
        `✓ File received: ${data.filename}\n` +
        `  Saved to: ${data.downloadPath}\n` +
        `  Hash verified ✓`
      )
    } else {
      Chat.appendSystem(
        `⚠ File received but HASH MISMATCH: ${data.filename}\n` +
        `  Expected: ${data.expectedHash}\n` +
        `  Got:      ${data.actualHash}\n` +
        `  File may be corrupted — use with caution`
      )
    }
  },
}

function _escHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

function _formatBytes(bytes) {
  if (!bytes) return 'unknown size'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}
