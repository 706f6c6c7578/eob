package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "os/user"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"
)

type Session struct {
    CurrentDir string
    LastAccess time.Time
}

func generateSessionID() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}

func withSession(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        logRequest(r)

        sessionID, err := r.Cookie("session_id")
        if err != nil || sessionID == nil {
            sessionID = &http.Cookie{
                Name:     "session_id",
                Value:    generateSessionID(),
                HttpOnly: true,
                Path:     "/",
            }
            http.SetCookie(w, sessionID)
            sessionStore.Lock()
            sessionStore.sessions[sessionID.Value] = Session{
                CurrentDir: originalRoot,
                LastAccess: time.Now(),
            }
            sessionStore.Unlock()
            fmt.Printf("New session created: %s\n", sessionID.Value)
        } else {
            sessionStore.Lock()
            if _, exists := sessionStore.sessions[sessionID.Value]; !exists {
                newSessionID := generateSessionID()
                sessionID.Value = newSessionID
                http.SetCookie(w, sessionID)
                sessionStore.sessions[newSessionID] = Session{
                    CurrentDir: originalRoot,
                    LastAccess: time.Now(),
                }
                fmt.Printf("Existing session not found, new session created: %s\n", newSessionID)
            } else {
                session := sessionStore.sessions[sessionID.Value]
                session.LastAccess = time.Now()
                sessionStore.sessions[sessionID.Value] = session
                fmt.Printf("Existing session found: %s\n", sessionID.Value)
            }
            sessionStore.Unlock()
        }

        sessionStore.Lock()
        currentSession := sessionStore.sessions[sessionID.Value]
        sessionStore.Unlock()

        fn(w, r, currentSession.CurrentDir)
    }
}

func logRequest(r *http.Request) {
    fmt.Printf("[%s] %s %s\n", r.RemoteAddr, r.Method, r.URL)
}

func listFiles(w http.ResponseWriter, r *http.Request, currentDir string) {
    fmt.Printf("Listing files in directory: %s\n", currentDir)

    cmd := exec.Command("ls", "-la", currentDir)
    output, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, fmt.Sprintf("Error executing command: %s", err), http.StatusInternalServerError)
        return
    }

    // Gib die Ausgabe zurück
    fmt.Fprintf(w, "%s", output)
}

func uploadFile(w http.ResponseWriter, r *http.Request, currentDir string) {
    err := r.ParseMultipartForm(10 << 20)
    if err != nil {
        http.Error(w, "Error parsing form", http.StatusBadRequest)
        return
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Error retrieving file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    filePath := filepath.Join(currentDir, handler.Filename)
    if !isPathSafe(filePath) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    out, err := os.Create(filePath)
    if err != nil {
        http.Error(w, "Error creating file", http.StatusInternalServerError)
        return
    }
    defer out.Close()

    _, err = io.Copy(out, file)
    if err != nil {
        http.Error(w, "Error writing file", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "File uploaded successfully")
}

func downloadFile(w http.ResponseWriter, r *http.Request, currentDir string) {
    fileName := r.URL.Query().Get("file")
    filePath := filepath.Join(currentDir, fileName)

    if !isPathSafe(filePath) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    file, err := os.Open(filePath)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        http.Error(w, "Error getting file info", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
    w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
    io.Copy(w, file)
}

func deleteFile(w http.ResponseWriter, r *http.Request, currentDir string) {
    fileName := r.URL.Query().Get("file")
    filePath := filepath.Join(currentDir, fileName)

    if !isPathSafe(filePath) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    fileInfo, err := os.Stat(filePath)
    if err != nil {
        http.Error(w, "Error accessing file", http.StatusInternalServerError)
        return
    }

    stat, ok := fileInfo.Sys().(*syscall.Stat_t)
    if !ok {
        http.Error(w, "Could not get file owner info", http.StatusInternalServerError)
        return
    }

    currentUser, err := user.Current()
    if err != nil {
        http.Error(w, "Could not determine current user", http.StatusInternalServerError)
        return
    }

    uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
    if err != nil {
        http.Error(w, "Error parsing UID", http.StatusInternalServerError)
        return
    }

    if stat.Uid != uint32(uid) {
        http.Error(w, "Permission denied: you can only delete files you own", http.StatusForbidden)
        return
    }

    err = os.Remove(filePath)
    if err != nil {
        log.Printf("Error deleting file: %v", err)
        http.Error(w, "Error deleting file", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "File deleted successfully")
}

func changeDirectory(w http.ResponseWriter, r *http.Request, currentDir string) {
    dirName := r.URL.Query().Get("dir")
    dirName = strings.Trim(dirName, `/\ "`)

    if dirName == "" {
        http.Error(w, "Invalid directory name", http.StatusBadRequest)
        return
    }

    var newDir string
    switch dirName {
    case "..":
        newDir = filepath.Dir(currentDir)
    case "root":
        newDir = originalRoot
    default:
        newDir = filepath.Join(currentDir, dirName)
        newDir = filepath.Clean(newDir)
    }

    info, err := os.Stat(newDir)
    if err != nil {
        if os.IsNotExist(err) {
            http.Error(w, "Directory not found", http.StatusNotFound)
        } else {
            http.Error(w, "Error accessing directory", http.StatusInternalServerError)
        }
        return
    }
    if !info.IsDir() {
        http.Error(w, "Not a directory", http.StatusBadRequest)
        return
    }

    if !isPathSafe(newDir) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    sessionID, err := r.Cookie("session_id")
    if err != nil || sessionID == nil {
        http.Error(w, "Session error", http.StatusInternalServerError)
        return
    }

    sessionStore.Lock()
    sessionStore.sessions[sessionID.Value] = Session{
        CurrentDir: newDir,
        LastAccess: time.Now(),
    }
    sessionStore.Unlock()

    fmt.Fprintf(w, "Directory changed to %s", newDir)
}

func createDirectory(w http.ResponseWriter, r *http.Request, currentDir string) {
    dirName := r.URL.Query().Get("dir")
    dirName = strings.Trim(dirName, `/\ "`)
    if dirName == "" {
        http.Error(w, "Invalid directory name", http.StatusBadRequest)
        return
    }

    dirPath := filepath.Join(currentDir, dirName)
    dirPath = filepath.Clean(dirPath)

    if !isPathSafe(dirPath) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    err := os.Mkdir(dirPath, 0755)
    if err != nil {
        http.Error(w, "Error creating directory", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "Directory created")
}

func viewFile(w http.ResponseWriter, r *http.Request, currentDir string) {
    fileName := r.URL.Query().Get("file")
    filePath := filepath.Join(currentDir, fileName)

    if !isPathSafe(filePath) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    file, err := os.Open(filePath)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        http.Error(w, "Error getting file info", http.StatusInternalServerError)
        return
    }

    if fileInfo.IsDir() {
        http.Error(w, "Cannot view directory content", http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "text/plain")
    io.Copy(w, file)
}

func handleQuit(w http.ResponseWriter, r *http.Request, currentDir string) {
    sessionID, err := r.Cookie("session_id")
    if err == nil && sessionID != nil {
        sessionStore.Lock()
        delete(sessionStore.sessions, sessionID.Value)
        sessionStore.Unlock()
    }

    fmt.Fprintln(w, "Connection closed")
}

func isPathSafe(path string) bool {
    absPath, _ := filepath.Abs(path)
    absRoot, _ := filepath.Abs(originalRoot)
    return strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absRoot))
}