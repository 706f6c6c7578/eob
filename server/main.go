package main

import (
    "context"
    "flag"
    "log"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "sync"
    "syscall"
    "time"

    "github.com/cretz/bine/tor"
    "github.com/awnumar/memguard"
)

var (
    originalRoot string
    sessionStore = struct {
        sync.Mutex
        sessions map[string]Session
    }{sessions: make(map[string]Session)}
)

type Config struct {
    duration    time.Duration
    port        int
    password    *memguard.LockedBuffer
    torDataDir  string
    enableMail  bool
}

func main() {
    // Flag parsing
    duration := flag.Duration("d", 1440*time.Minute, "Duration between address rotations (Default: 1440 minutes = 1 day)")
    port := flag.Int("p", 8080, "Local port to forward")
    password := flag.String("s", "", "Encryption password (required)")
    torDataDir := flag.String("t", "", "Tor data directory")
    enableMail := flag.Bool("m", false, "Enable email notifications")
    rootFolder := flag.String("f", "", "Root folder for file management")
    flag.Parse()

    if *password == "" || *rootFolder == "" {
        log.Fatal("Password and root folder are required")
    }

    absRoot, err := filepath.Abs(*rootFolder)
    if err != nil {
        log.Fatalf("Invalid root path: %v", err)
    }
    originalRoot = absRoot

    config := &Config{
        duration:    *duration,
        port:        *port,
        password:    memguard.NewBufferFromBytes([]byte(*password)),
        torDataDir:  *torDataDir,
        enableMail:  *enableMail,
    }

    // Handle graceful shutdown
    shutdown := make(chan os.Signal, 1)
    signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

    // Setup API endpoints
    setupAPI()

    // Register handlers for file operations
    http.HandleFunc("/files", withSession(listFiles))       // List files
    http.HandleFunc("/upload", withSession(uploadFile))     // Upload a file
    http.HandleFunc("/download", withSession(downloadFile)) // Download a file
    http.HandleFunc("/delete", withSession(deleteFile))     // Delete a file
    http.HandleFunc("/cd", withSession(changeDirectory))    // Change directory
    http.HandleFunc("/mkdir", withSession(createDirectory)) // Create a directory
    http.HandleFunc("/cat", withSession(viewFile))          // View file content
    http.HandleFunc("/quit", withSession(handleQuit))       // Quit the session

    // Start Tor once (single instance)
    ctx := context.Background()
    t, err := tor.Start(ctx, &tor.StartConf{
        DataDir: config.torDataDir,
        NoHush:  true,
    })
    if err != nil {
        log.Fatalf("Failed to start Tor: %v", err)
    }
    defer t.Close()

    // Main service loop
    for {
        select {
        case <-shutdown:
            log.Println("Shutting down gracefully...")
            return
        default:
            if err := runServiceCycle(ctx, t, config); err != nil {
                log.Printf("Service cycle failed: %v (retrying in 5 seconds)", err)
                time.Sleep(5 * time.Second)
            }
        }
    }
}