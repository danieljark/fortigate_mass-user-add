# FortiGate CSV User Import

Kleine Python-3-Anwendung zum Anlegen lokaler Benutzer aus CSV, Setzen von Passwörtern, Zuweisen zu Gruppen und automatischem FortiToken-Mapping.

## Voraussetzungen (FortiGate)
- REST API Admin mit ausreichenden Rechten (mindestens Read/Write fuer **User & Authentication**).
- API-Zugriff aktiviert und vom ausfuehrenden Host erlaubt.
- FortiToken-Objekte muessen im System vorhanden sein (Hardware/Cloud je nach Lizenz).

## Genutzte Endpoints (FortiOS CMDB)
- Benutzer anlegen/aktualisieren: `/api/v2/cmdb/user/local`
- Benutzer lesen/aktualisieren: `/api/v2/cmdb/user/local/<username>`
- Gruppe lesen/aktualisieren: `/api/v2/cmdb/user/group/<group>`
- FortiToken-Listen (Fallback je nach Version):
  - `/api/v2/cmdb/user/fortitoken`
  - `/api/v2/cmdb/user/fortitoken2`

Token-Zuweisung erfolgt primaer ueber Update des lokalen Users (`two-factor=fortitoken`, `fortitoken=<serial>`). Falls das fehlschlaegt, versucht das Skript zusaetzlich die Token-Objekte zu aktualisieren.

## Beispiel CSV
```csv
username,password,email,group
alice,ChangeMe123,alice@example.com,VPN_Users
bob,ChangeMe123,bob@example.com,VPN_Users
```

## Konfiguration (.conf)
Standardpfad: `fg_import.conf`

Beispiel:
```ini
[fortigate]
host = https://fgt.example.local
token = <API_TOKEN>
vdom = root
verify = false
```

Wenn `host` oder `token` fehlen und ein Terminal vorhanden ist, fragt das Skript die Werte interaktiv ab und bietet an, sie zu speichern.

## Beispiel Aufruf
```bash
python3 fg_csvuser_import.py --csv users.csv --host https://fgt.example.local --token <API_TOKEN>
```
Optional:
```bash
python3 fg_csvuser_import.py --csv users.csv --config fg_import.conf --dry-run
```

## Export bestehender User
```bash
python3 fg_csvuser_import.py --export-users users_export.csv --config fg_import.conf
```

Hinweis: Das Export-CSV nutzt dieselben Header (`username,password,email,group`). `password` bleibt leer. Falls ein User in mehreren Gruppen ist, wird die alphabetisch erste Gruppe exportiert.
