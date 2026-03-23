/**
 * Settings — profile management, decoy config, sound, download dir
 *
 * All config keys use lowercase snake_case to match Go JSON struct tags.
 */

export const Settings = {

  init(app) {
    document.getElementById('btn-save-settings').addEventListener('click', () => {
      this.save(app)
    })

    document.getElementById('btn-add-profile').addEventListener('click', () => {
      this.addProfileRow(app, {
        name:      'New Server',
        host:      'localhost',
        port:      37842,
        cert_file: 'chat_public.pem',
        username:  'User',
      })
    })
  },

  // Populate the connection screen's profile dropdown
  populateConnectScreen(config) {
    const select = document.getElementById('profile-select')
    select.innerHTML = ''

    const profiles = config.profiles || config.Profiles || []

    if (profiles.length === 0) {
      const opt = document.createElement('option')
      opt.textContent = 'Custom'
      opt.value = -1
      select.appendChild(opt)
      return
    }

    const lastIdx = config.last_profile || config.LastProfile || 0

    profiles.forEach((p, i) => {
      const opt = document.createElement('option')
      opt.value = i
      opt.textContent = p.name || p.Name || 'Server'
      if (i === lastIdx) opt.selected = true
      select.appendChild(opt)
    })

    // Pre-fill fields from last used profile
    const last = profiles[lastIdx]
    if (last) {
      document.getElementById('input-host').value     = last.host     || last.Host     || ''
      document.getElementById('input-port').value     = last.port     || last.Port     || 37842
      document.getElementById('input-username').value = last.username || last.Username || ''
      document.getElementById('input-cert').value     = last.cert_file || last.CertFile || ''
    }
  },

  openModal(config) {
    if (!config) return

    // Populate settings fields using lowercase keys with uppercase fallbacks
    const dec = document.getElementById('setting-decoy')
    dec.checked = !!(config.decoy_enabled ?? config.DecoyEnabled)
    document.getElementById('setting-decoy-interval').value = config.decoy_interval || config.DecoyInterval || 30
    document.getElementById('setting-decoy-min').value      = config.decoy_min_bytes || config.DecoyMinBytes || 100
    document.getElementById('setting-decoy-max').value      = config.decoy_max_bytes || config.DecoyMaxBytes || 500
    document.getElementById('setting-sound').checked        = !!(config.sound_enabled ?? config.SoundEnabled)
    document.getElementById('setting-download-dir').value   = config.download_dir || config.DownloadDir || ''

    // Render profiles
    const list = document.getElementById('profiles-list')
    list.innerHTML = ''
    const profiles = config.profiles || config.Profiles || []
    profiles.forEach(p => this.addProfileRow(null, p, list))

    document.getElementById('modal-settings').classList.remove('hidden')
  },

  addProfileRow(app, profile, containerEl) {
    const list = containerEl || document.getElementById('profiles-list')

    const row = document.createElement('div')
    row.className = 'profile-row'
    row.innerHTML = `
      <input type="text"   class="pf-name"     value="${_esc(profile.name     || profile.Name     || '')}" placeholder="Name" style="flex:2" />
      <input type="text"   class="pf-host"     value="${_esc(profile.host     || profile.Host     || '')}" placeholder="host" style="flex:2" />
      <input type="number" class="pf-port"     value="${     profile.port     || profile.Port     || 37842}"               style="width:70px" />
      <input type="text"   class="pf-username" value="${_esc(profile.username || profile.Username || '')}" placeholder="user" style="flex:1" />
      <input type="text"   class="pf-cert"     value="${_esc(profile.cert_file || profile.CertFile || '')}" placeholder="cert" style="flex:1.5" />
      <button class="btn btn-secondary btn-sm pf-cert-browse" type="button">Browse</button>
      <button class="btn btn-ghost btn-icon btn-sm pf-remove" title="Remove" style="color:var(--red)">✕</button>`

    row.querySelector('.pf-remove').addEventListener('click', () => row.remove())
    row.querySelector('.pf-cert-browse').addEventListener('click', async () => {
        try {
            const path = await window.go.main.App.PickFile()
            if (path) row.querySelector('.pf-cert').value = path
        } catch (e) {
            console.error(e)
        }
    })
    list.appendChild(row)
  },

  async save(app) {
    const config = { ...app.config }

    // Write all keys in lowercase snake_case to match Go JSON struct tags
    config.decoy_enabled   = document.getElementById('setting-decoy').checked
    config.decoy_interval  = parseInt(document.getElementById('setting-decoy-interval').value) || 30
    config.decoy_min_bytes = parseInt(document.getElementById('setting-decoy-min').value) || 100
    config.decoy_max_bytes = parseInt(document.getElementById('setting-decoy-max').value) || 500
    config.sound_enabled   = document.getElementById('setting-sound').checked
    config.download_dir    = document.getElementById('setting-download-dir').value.trim()

    // Read profiles — all lowercase keys
    const rows = document.querySelectorAll('#profiles-list .profile-row')
    config.profiles = Array.from(rows).map(row => ({
      name:      row.querySelector('.pf-name').value.trim(),
      host:      row.querySelector('.pf-host').value.trim(),
      port:      parseInt(row.querySelector('.pf-port').value) || 37842,
      username:  row.querySelector('.pf-username').value.trim(),
      cert_file: row.querySelector('.pf-cert').value.trim(),
    })).filter(p => p.host)

    // Remove stale uppercase keys if present from old sessions
    delete config.Profiles
    delete config.DecoyEnabled
    delete config.DecoyInterval
    delete config.DecoyMinBytes
    delete config.DecoyMaxBytes
    delete config.SoundEnabled
    delete config.DownloadDir

    try {
      await window.go.main.App.SaveConfig(config)
      app.config = config
      Settings.populateConnectScreen(config)
      app.closeModal('modal-settings')
    } catch (e) {
      alert('Failed to save settings: ' + e)
    }
  },
}

function _esc(s) {
  return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}