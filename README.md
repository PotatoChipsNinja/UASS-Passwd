# UASS-Passwd
## Feature
- Change CCB UASS password via CLI
- Retain current password, bypass historical password restrictions of UASS

## Build
``` bash
go build
```

## Usage
``` bash
chmod +x uass-passwd

# interactive mode
./uass-passwd

# command line arguments mode
./uass-passwd <username> <old_password> <new_password>
```
