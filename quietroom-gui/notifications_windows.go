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

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Wails registers the app for toast notifications under the executable's
// file name (HKCU\Software\Classes\AppUserModelId\<file name>), and Windows
// shows that name on every notification, for example
// "quietroom_client_gui-windows-amd64-v3.0.0.exe". Because the file name
// contains the version, each version also leaves its own registration
// behind: that key, a COM activation key (CLSID\{GUID}) pointing at the old
// executable, and an icon file in the temporary folder.

const (
	appModelRoot = `Software\Classes\AppUserModelId\`
	clsidRoot    = `Software\Classes\CLSID\`
)

var guidPattern = regexp.MustCompile(`^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$`)

// afterWailsNotificationsInit names the app "QuietRoom" in notifications
// and removes the registrations of other QuietRoom executables.
func afterWailsNotificationsInit() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	current := filepath.Base(exe)
	if k, err := registry.OpenKey(registry.CURRENT_USER, appModelRoot+current, registry.SET_VALUE); err == nil {
		k.SetStringValue("DisplayName", "QuietRoom")
		k.Close()
	}
	removeOldRegistrations(current)
}

func removeOldRegistrations(current string) {
	root, err := registry.OpenKey(registry.CURRENT_USER, strings.TrimSuffix(appModelRoot, `\`), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	names, _ := root.ReadSubKeyNames(-1)
	root.Close()
	for _, name := range names {
		if strings.EqualFold(name, current) || !isQuietRoomExe(name) {
			continue
		}
		if k, err := registry.OpenKey(registry.CURRENT_USER, appModelRoot+name, registry.QUERY_VALUE); err == nil {
			guid, _, _ := k.GetStringValue("CustomActivator")
			k.Close()
			if guidPattern.MatchString(guid) && !guidInUse(guid, current) {
				registry.DeleteKey(registry.CURRENT_USER, clsidRoot+guid+`\LocalServer32`)
				registry.DeleteKey(registry.CURRENT_USER, clsidRoot+guid)
				os.Remove(filepath.Join(os.TempDir(), name+guid+".png"))
			}
		}
		registry.DeleteKey(registry.CURRENT_USER, `Software\`+name+`\NotificationCategories`)
		registry.DeleteKey(registry.CURRENT_USER, `Software\`+name) // only if now empty
		registry.DeleteKey(registry.CURRENT_USER, appModelRoot+name)
	}
}

// guidInUse reports whether the current executable's registration uses guid
// (never the case with Wails' per-name GUIDs, but never delete it then).
func guidInUse(guid, current string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, appModelRoot+current, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	cur, _, _ := k.GetStringValue("CustomActivator")
	return strings.EqualFold(cur, guid)
}
