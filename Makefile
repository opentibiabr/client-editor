all:
	go run main.go

test:
	go build main.go && chmod +x main && ./main ~/Downloads/client.exe https://open.tibia.io/login.php

build:
	GOOS=windows GOARCH=386 go build -o client-editor-x86.exe main.go
	GOOS=windows GOARCH=amd64 go build -o client-editor-x64.exe main.go
	GOOS=linux GOARCH=386 go build -o client-editor-x86 main.go
	GOOS=linux GOARCH=amd64 go build -o client-editor-x64 main.go
