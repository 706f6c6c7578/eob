package main

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/smtp"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "crypto/tls"
    "strconv"
    "github.com/cretz/bine/tor"
)

const keyDerivationSalt = "ephemeral_onion_salt_secure"

var (
    currentOnionAddress string
    currentValidUntil   time.Time
    mu                  sync.Mutex // Mutex zum Synchronisieren des Zugriffs
)

func deriveKey(password []byte) string {
    key := argon2.IDKey(
        password,
        []byte(keyDerivationSalt),
        3,          // Iterations
        64*1024,    // Memory
        4,          // Threads
        32,         // Key length
    )
    return hex.EncodeToString(key)
}

func encryptMessage(message string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func sendNotification(onionID, port, hexKey string, validUntil time.Time, duration time.Duration) error {
    // Decode the hex key into a byte array
    key, err := hex.DecodeString(hexKey)
    if err != nil {
        return fmt.Errorf("failed to decode hex key: %w", err)
    }

    // Read subscribers from the file
    subscribers, err := ioutil.ReadFile("subscribers.txt")
    if err != nil {
        return fmt.Errorf("failed to read subscribers: %w", err)
    }

    // Create an SMTP client with TLS-Skip-Verify
    client, err := smtp.Dial("localhost:25")
    if err != nil {
        return fmt.Errorf("SMTP connection failed: %w", err)
    }
    defer client.Close()

    // Enable STARTTLS with SkipVerify
    if err := client.StartTLS(&tls.Config{
        InsecureSkipVerify: true, // Skip certificate verification
    }); err != nil {
        return fmt.Errorf("STARTTLS failed: %w", err)
    }

    // Create the plaintext message
    plaintext := fmt.Sprintf("Onion Address: http://%s.onion\nPort: %s\nValid Until: %s UTC\nDuration: %v",
        onionID, port, validUntil.Format("2006-01-02 15:04:05"), duration)
    encryptedMessage, err := encryptMessage(plaintext, key)
    if err != nil {
        return fmt.Errorf("encryption failed: %w", err)
    }

    // Email template (only the encrypted message is included)
    emailTemplate := "From: Onion Courier <noreply@oc2mx.net>\n" +
        "To: %s\n" +
        "Subject: New Onion Address\n\n" +
        "%s"

    // Send an email to each subscriber
    for _, email := range strings.Split(string(subscribers), "\n") {
        email = strings.TrimSpace(email)
        if email == "" {
            continue
        }

        // Reset for each email
        if err := client.Mail("noreply@oc2mx.net"); err != nil {
            log.Printf("Mail command failed for %s: %v", email, err)
            continue
        }
        if err := client.Rcpt(email); err != nil {
            log.Printf("Rcpt command failed for %s: %v", email, err)
            continue
        }

        // Write email data
        w, err := client.Data()
        if err != nil {
            log.Printf("Data command failed for %s: %v", email, err)
            continue
        }

        // Insert only the encrypted message into the email
        msg := fmt.Sprintf(emailTemplate, email, encryptedMessage)
        if _, err := fmt.Fprintf(w, msg); err != nil {
            log.Printf("Failed to write email to %s: %v", email, err)
            continue
        }
        if err := w.Close(); err != nil {
            log.Printf("Failed to close email to %s: %v", email, err)
        }
    }

    return client.Quit()
}

func setupAPI() {
    http.HandleFunc("/api/onion", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        defer mu.Unlock()

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "onionAddress": fmt.Sprintf("http://%s.onion", currentOnionAddress),
            "validUntil":   currentValidUntil.Format("2006-01-02 15:04:05"),
        })
    })
}

func runServiceCycle(ctx context.Context, t *tor.Tor, config *Config) error {
    onion, err := t.Listen(ctx, &tor.ListenConf{
        Version3:    true,
        RemotePorts: []int{80},
    })
    if err != nil {
        return fmt.Errorf("onion creation failed: %w", err)
    }
    defer onion.Close()

    onionAddress := onion.ID
    validUntil := time.Now().Add(config.duration)

    // Aktualisiere die globalen Onion-Daten
    mu.Lock()
    currentOnionAddress = onionAddress
    currentValidUntil = validUntil
    mu.Unlock()

    hexKey := deriveKey(config.password.Bytes())

    // Send email notification if enabled
    if config.enableMail {
        if err := sendNotification(onion.ID, strconv.Itoa(config.port), hexKey, validUntil, config.duration); err != nil {
            log.Printf("Failed to send notifications: %v", err)
        }
    }

    log.Printf(`
=== NEW ONION SERVICE ===
Address: http://%s.onion
Local:   http://localhost:%d
Key:     %s
Valid until: %s UTC
Duration: %v
=========================`,
    onion.ID, config.port, hexKey,
    validUntil.Format("2006-01-02 15:04:05"), config.duration)

    // Start HTTP server
    server := &http.Server{
        Addr:    fmt.Sprintf("127.0.0.1:%d", config.port),
        Handler: nil, // Verwende den DefaultServeMux mit den registrierten Handlern
    }
    defer server.Shutdown(context.Background())

    go func() {
        if err := server.Serve(onion); err != nil && err != http.ErrServerClosed {
            log.Printf("HTTP server error: %v", err)
        }
    }()

    select {
    case <-time.After(config.duration):
        log.Println("Rotating to new onion address...")
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}