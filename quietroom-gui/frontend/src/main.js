import { App } from './app.js'

// Make App globally accessible for onclick handlers in HTML
window.App = App

// Boot
App.init()
