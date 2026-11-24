import { writeFileSync } from 'node:fs'
import { defineConfig } from 'vite'

// The build output in dist/ is generated and not committed; only the empty
// dist/.gitkeep is, so that the GUI's //go:embed all:frontend/dist compiles
// on a fresh clone. emptyOutDir deletes it on every build, so put it back.
const keepDist = {
  name: 'keep-dist-placeholder',
  closeBundle() {
    writeFileSync(new URL('./dist/.gitkeep', import.meta.url), '')
  },
}

export default defineConfig({
  plugins: [keepDist],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
