package main

import (
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "golang.org/x/net/proxy"
)

var sessionID string

func printUsage() {
    fmt.Println("Usage: obc <server URL>")
    fmt.Println("\nConnects to an Onion Box server over the Tor network.")
    fmt.Println("\nCommands available after connection:")
    fmt.Println("  ls                 List files in the current directory")
    fmt.Println("  cat <file>         View file content")
    fmt.Println("  cd <dir>           Change to a different directory")
    fmt.Println("  put <file>         Put a file on the server")
    fmt.Println("  get <file>         Get a file from the server")
    fmt.Println("  rm <file>          Remove a file on the server")
    fmt.Println("  mkdir <dir>        Create a new directory")
    fmt.Println("  quit               Quit the connection")
    fmt.Println("\nExample:")
    fmt.Println("  obc <onion URL>:8080")
    fmt.Println("\nNote: Ensure the Tor service is running on 127.0.0.1:9050.")
}

func main() {
    if len(os.Args) != 2 {
        printUsage()
        return
    }
    serverURL := os.Args[1]
    if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
        serverURL = "http://" + serverURL
    }

    dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
    if err != nil {
        fmt.Println("Error connecting to Tor:", err)
        return
    }
    httpTransport := &http.Transport{
        Dial: dialer.Dial,
    }
    client := &http.Client{
        Transport: httpTransport,
    }
    fmt.Println("Connecting to Onion Box...")
    resp, err := client.Get(serverURL + "/files")
    if err != nil {
        fmt.Println("Error connecting to server:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    fmt.Println("Connection successful!")
    for _, cookie := range resp.Cookies() {
        if cookie.Name == "session_id" {
            sessionID = cookie.Value
            break
        }
    }
    for {
        fmt.Print("\nls, cat <file>, cd <dir>, put <file>, get <file>, rm <file>, mkdir <dir>, quit: ")
        var command, arg string
        fmt.Scanln(&command, &arg)
        switch command {
        case "ls":
            listFiles(client, serverURL)
        case "put":
            if arg == "" {
                fmt.Println("Error: missing file name")
                continue
            }
            uploadFile(client, serverURL, arg)
        case "get":
            if arg == "" {
                fmt.Println("Error: missing file name")
                continue
            }
            downloadFile(client, serverURL, arg)
        case "rm":
            if arg == "" {
                fmt.Println("Error: missing file name")
                continue
            }
            deleteFile(client, serverURL, arg)
        case "cd":
            if arg == "" {
                fmt.Println("Error: missing directory name")
                continue
            }
            changeDirectory(client, serverURL, arg)
        case "mkdir":
            if arg == "" {
                fmt.Println("Error: missing directory name")
                continue
            }
            createDirectory(client, serverURL, arg)
        case "cat":
            if arg == "" {
                fmt.Println("Error: missing file name")
                continue
            }
            viewFile(client, serverURL, arg)
        case "quit":
            quit(client, serverURL)
            return
        default:
            fmt.Println("Unknown command")
        }
    }
}

func viewFile(client *http.Client, serverURL, fileName string) {
    req, err := http.NewRequest("GET", serverURL+"/cat?file="+fileName, nil)
    if err != nil {
        fmt.Println("Error viewing file:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error viewing file:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    io.Copy(os.Stdout, resp.Body)
    fmt.Println()
}

func listFiles(client *http.Client, serverURL string) {
    req, err := http.NewRequest("GET", serverURL+"/files", nil)
    if err != nil {
        fmt.Println("Error listing files:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error listing files:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    io.Copy(os.Stdout, resp.Body)
    fmt.Println()
}

func uploadFile(client *http.Client, serverURL, filePath string) {
    file, err := os.Open(filePath)
    if err != nil {
        fmt.Println("Error opening file:", err)
        return
    }
    defer file.Close()

    pr, pw := io.Pipe()
    defer pr.Close()

    writer := multipart.NewWriter(pw)
    go func() {
        defer pw.Close()
        defer writer.Close()

        part, err := writer.CreateFormFile("file", filepath.Base(filePath))
        if err != nil {
            fmt.Println("Error creating form file:", err)
            return
        }

        if _, err := io.Copy(part, file); err != nil {
            fmt.Println("Error copying file:", err)
            return
        }
    }()

    req, err := http.NewRequest("POST", serverURL+"/upload", pr)
    if err != nil {
        fmt.Println("Error creating request:", err)
        return
    }

    req.Header.Set("Content-Type", writer.FormDataContentType())
    addSessionCookie(req)

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error uploading file:", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }

    fmt.Println("\nFile uploaded successfully")
    fmt.Println()
}

func downloadFile(client *http.Client, serverURL, fileName string) {
    req, err := http.NewRequest("GET", serverURL+"/download?file="+fileName, nil)
    if err != nil {
        fmt.Println("Error downloading file:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error downloading file:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    out, err := os.Create(fileName)
    if err != nil {
        fmt.Println("Error creating file:", err)
        return
    }
    defer out.Close()
    io.Copy(out, resp.Body)
    fmt.Println("File downloaded successfully")
    fmt.Println()
}

func deleteFile(client *http.Client, serverURL, fileName string) {
    req, err := http.NewRequest(http.MethodDelete, serverURL+"/delete?file="+fileName, nil)
    if err != nil {
        fmt.Println("Error creating request:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error deleting file:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    io.Copy(os.Stdout, resp.Body)
    fmt.Println()
}

func changeDirectory(client *http.Client, serverURL, dirName string) {
    req, err := http.NewRequest("GET", serverURL+"/cd?dir="+dirName, nil)
    if err != nil {
        fmt.Println("Error changing directory:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error changing directory:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    io.Copy(os.Stdout, resp.Body)
    fmt.Println()
}

func createDirectory(client *http.Client, serverURL, dirName string) {
    req, err := http.NewRequest("GET", serverURL+"/mkdir?dir="+dirName, nil)
    if err != nil {
        fmt.Println("Error creating directory:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error creating directory:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    io.Copy(os.Stdout, resp.Body)
    fmt.Println()
}

func quit(client *http.Client, serverURL string) {
    req, err := http.NewRequest("GET", serverURL+"/quit", nil)
    if err != nil {
        fmt.Println("Error closing connection:", err)
        return
    }
    addSessionCookie(req)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error closing connection:", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        fmt.Println("Server returned an error:", resp.Status)
        return
    }
    fmt.Println("Connection closed")
    fmt.Println()
}

func addSessionCookie(req *http.Request) {
    if sessionID != "" {
        req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
    }
}
