package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/joshhartwig/chirpy/internal/database"

	_ "github.com/lib/pq"
)

// our user account struct
type User struct {
	ID         uuid.UUID `json:"id"`
	Created_At time.Time `json:"created_at"`
	Updated_At time.Time `json:"updated_at"`
	Email      string    `json:"email"`
}

type CreateChirpRequest struct {
	Body    string `json:"body"`
	User_Id string `json:"user_id"`
}

// used to manage configuration for server
type apiConfig struct {
	fileServerHits atomic.Int32
	db             *database.Queries
	platform       string
}

// middlewareMetricsInc is a middleware function that increments the file server hit counter
// and adds a "Cache-Control: no-cache" header to the response. It then calls the next handler
// in the chain.
func (a *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "no-cache")
		a.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// middlewareMetricsReport is an HTTP handler function that sets specific headers
// and writes an HTML response to the client. The response includes a welcome message
// and the number of times the file server has been accessed.
func (a *apiConfig) middlewareMetricsReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache")
	w.Header().Add("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf(`
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>`, a.fileServerHits.Load()))
}

func (a *apiConfig) middlewareMetricsReset(w http.ResponseWriter, r *http.Request) {
	if a.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	a.db.DeleteAllUsers(r.Context())
	w.WriteHeader(http.StatusOK)
	a.fileServerHits.Store(0)
}

func main() {
	godotenv.Load()              // load env vars
	dbURL := os.Getenv("DB_URL") // fetch the db_url connection string
	platform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL) // open the db w/ sql.open
	if err != nil {
		log.Fatalf("error opening db %v", err)
		return
	}

	port := "8080" // port for app
	filePathRoot := "."

	dbQueries := database.New(db)

	apiCfg := apiConfig{
		fileServerHits: atomic.Int32{},
		db:             dbQueries,
		platform:       platform,
	}

	// create a router (aka mux) for our project
	mux := http.NewServeMux()

	// create a new server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// host/app
	mux.Handle("/app/", apiCfg.middlewareMetricsInc((http.StripPrefix("/app", http.FileServer(http.Dir(filePathRoot))))))

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		badWords := []string{
			"kerfuffle",
			"sharbert",
			"fornax",
		}

		type ChirpRequest struct {
			Body string `json:"body"`
		}

		type ChirpResponse struct {
			Error        string `json:"error,omitempty"`
			Cleaned_Body string `json:"cleaned_body,omitempty"`
		}

		// sends a json response
		sendJSONResponse := func(w http.ResponseWriter, statusCode int, response ChirpResponse) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(response)
		}

		var chirpReq ChirpRequest
		if err := json.NewDecoder(r.Body).Decode(&chirpReq); err != nil {
			log.Printf("Error decoding request: %s", err)
			sendJSONResponse(w, http.StatusInternalServerError, ChirpResponse{
				Error: "Failed to decode request body",
			})
			return
		}

		if len(chirpReq.Body) > 140 {
			log.Printf("Chirp body is too long: %d chars", len(chirpReq.Body))
			sendJSONResponse(w, http.StatusBadRequest, ChirpResponse{
				Error: "Chirp body exceeds 140 chars",
			})
			return
		}

		chirpReq.Body = cleanBadWords(chirpReq.Body, badWords)

		sendJSONResponse(w, http.StatusOK, ChirpResponse{
			Cleaned_Body: chirpReq.Body,
		})
	})

	// host/admin/metrics - displays visited count
	mux.HandleFunc("GET /admin/metrics", apiCfg.middlewareMetricsReport)
	mux.HandleFunc("POST /admin/reset", apiCfg.middlewareMetricsReset)

	// /api/reset
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "text/plain;charset=utf-8")
		io.WriteString(w, "OK")
	})

	// api/users
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type req struct {
			Email string `json:"email"`
		}

		var userReq req
		if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
			log.Printf("Error decoding request: %s", err)
		}

		user, err := dbQueries.CreateUser(r.Context(), userReq.Email)
		if err != nil {
			log.Printf("error creating user in database %s", err)
		}

		dbUser := User{
			ID:         user.ID,
			Created_At: user.CreatedAt,
			Updated_At: user.UpdatedAt,
			Email:      user.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(dbUser)
	})

	log.Printf("serving files from %s on port: %s\n", filePathRoot, port)
	// start the server and check for any errors
	log.Fatal(srv.ListenAndServe())
}

// per spec, remove 'bad words'
func cleanBadWords(chirpToBeCleaned string, badWords []string) string {
	words := strings.Split(chirpToBeCleaned, " ")
	for idx, word := range words {
		for _, badword := range badWords {
			if strings.ToLower(word) == badword {
				words[idx] = "****"
			}
		}
	}

	rejoined := strings.Join(words, " ")
	return rejoined
}
