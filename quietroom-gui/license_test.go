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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGeneratedFilesLicensed fails when a generated frontend file lost its
// license header, for example after "wails dev", which runs no build hooks.
// Fix: node scripts/licenseheader.mjs (in quietroom-gui), then commit.
func TestGeneratedFilesLicensed(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.FromSlash(p))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(data), "\r\n", "\n")
	}
	header := read("scripts/license-header.txt")
	if !strings.HasPrefix(header, "// Copyright (C) 2026 darkfiber-lab\n") {
		t.Fatalf("scripts/license-header.txt is not the license header")
	}
	for _, rel := range []string{"frontend/wailsjs/go/models.ts"} {
		if !strings.HasPrefix(read(rel), header) {
			t.Errorf("%s has no license header: run 'node scripts/licenseheader.mjs' in quietroom-gui", rel)
		}
	}
}
