BINARY = ssh-honeypot
UNIT   = systemd/ssh-honeypot.service

.PHONY: build install

# static linux binary -- no libc dependency on the VPS
build:
	CGO_ENABLED=0 GOOS=linux go build -o $(BINARY) .

# run on the VPS after scp
install:
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	install -m 644 $(UNIT) /etc/systemd/system/ssh-honeypot.service
