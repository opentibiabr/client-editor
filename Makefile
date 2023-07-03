all:
	go run main.go

test:
	go build main.go && chmod +x main && ./main ~/Downloads/client.exe https://open.tibia.io/login.php

build:
	GOOS=windows GOARCH=386 go build -o client-editor-windows-x86.exe main.go
	GOOS=windows GOARCH=amd64 go build -o client-editor-windows-x64.exe main.go
	GOOS=linux GOARCH=386 go build -o client-editor-linux-x86 main.go
	GOOS=linux GOARCH=amd64 go build -o client-editor-linux-x64 main.go
	GOOS=darwin GOARCH=amd64 go build -o client-editor-darwin-x64 main.go
	GOOS=darwin GOARCH=arm64 go build -o client-editor-darwin-arm64 main.go
	zip client-editor-windows.zip client-editor-windows-* *.key
	zip client-editor-linux.zip client-editor-linux-* *.key 
	zip client-editor-darwin.zip client-editor-darwin-* *.key 

clean:
	rm -f *.zip client-editor