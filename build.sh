GOOS=darwin GOARCH=arm64 go build -o dist/vpn_arm64_darwin .
GOOS=darwin GOARCH=amd64 go build -o dist/vpn_amd64_darwin .
GOOS=windows GOARCH=amd64 go build -o dist/vpn_amd64_windows .
GOOS=linux GOARCH=amd64 go build -o dist/vpn_amd64_linux .