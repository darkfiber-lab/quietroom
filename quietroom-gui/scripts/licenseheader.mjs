// Copyright (C) 2026 darkfiber-lab

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Restores the license header on frontend files that Wails regenerates
// without it. Runs as a post-build hook (see wails.json); paths are
// resolved from this script's location, so the working directory does
// not matter. Run by hand after "wails dev": node scripts/licenseheader.mjs

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const header = readFileSync(join(root, 'scripts', 'license-header.txt'), 'utf8').replace(/\r\n/g, '\n')
const generated = ['frontend/wailsjs/go/models.ts']

for (const rel of generated) {
  const path = join(root, rel)
  const text = readFileSync(path, 'utf8')
  if (!text.replace(/\r\n/g, '\n').startsWith(header)) {
    writeFileSync(path, header + '\n\n' + text)
    console.log(`licenseheader: restored header on ${rel}`)
  }
}
