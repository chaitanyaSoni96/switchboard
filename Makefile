TAILWIND     := bin/tailwindcss
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
CSS_IN       := internal/web/assets/input.css
CSS_OUT      := internal/web/assets/style.css

.PHONY: build test css generate run clean install

# The generated CSS and templ Go files are checked in, so a plain `go build`
# works on a machine with neither tailwind nor templ installed.
# CGO_ENABLED=0 makes the result a genuinely static binary. Nothing here needs
# cgo — every address Switchboard dials is a loopback literal, so the pure-Go
# resolver is all it ever wanted.
build: generate
	CGO_ENABLED=0 go build -o bin/switchboard ./cmd/switchboard

test:
	go vet ./... && go test ./...

generate: css
	templ generate

css: $(TAILWIND)
	$(TAILWIND) -i $(CSS_IN) -o $(CSS_OUT) --minify

$(TAILWIND):
	mkdir -p bin
	curl -sSL -o $@ $(TAILWIND_URL)
	chmod +x $@

run: build
	./bin/switchboard --port 8090

# Installs to /usr/local/bin and enables the unit. Switchboard itself runs as
# the invoking user, not as root — see systemd/switchboard.service.
install: build
	sudo install -m 0755 bin/switchboard /usr/local/bin/switchboard
	sudo install -m 0644 systemd/switchboard.service /etc/systemd/system/switchboard.service
	sudo systemctl daemon-reload
	@echo "edit /etc/systemd/system/switchboard.service to set User=, then:"
	@echo "  sudo systemctl enable --now switchboard"

clean:
	rm -f bin/switchboard
