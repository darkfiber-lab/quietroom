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


export namespace main {
	
	export class ServerProfile {
	    name: string;
	    host: string;
	    port: number;
	    cert_file: string;
	    username: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerProfile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.cert_file = source["cert_file"];
	        this.username = source["username"];
	    }
	}
	export class AppConfig {
	    profiles: ServerProfile[];
	    last_profile: number;
	    sound_enabled: boolean;
	    decoy_enabled: boolean;
	    decoy_interval: number;
	    decoy_min_bytes: number;
	    decoy_max_bytes: number;
	    download_dir: string;
	
	    static createFrom(source: any = {}) {
	        return new AppConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profiles = this.convertValues(source["profiles"], ServerProfile);
	        this.last_profile = source["last_profile"];
	        this.sound_enabled = source["sound_enabled"];
	        this.decoy_enabled = source["decoy_enabled"];
	        this.decoy_interval = source["decoy_interval"];
	        this.decoy_min_bytes = source["decoy_min_bytes"];
	        this.decoy_max_bytes = source["decoy_max_bytes"];
	        this.download_dir = source["download_dir"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

