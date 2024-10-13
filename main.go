package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/joshhartwig/chirpy/internal/auth"
	"github.com/joshhartwig/chirpy/internal/database"

	_ "github.com/lib/pq"
)

const jwtTokenExiration int = 3600

// our user account struct
type User struct {
	ID            uuid.UUID `json:"id"`
	Created_At    time.Time `json:"created_at"`
	Updated_At    time.Time `json:"updated_at"`
	Email         string    `json:"email"`
	Token         string    `json:"token"`
	Refresh_Token string    `json:"refresh_token"`
}

type ChirpRequest struct {
	Body string `json:"body"`
}

type ChirpResponse struct {
	Error      string    `json:"error,omitempty"`
	Body       string    `json:"body,omitempty"`
	Id         uuid.UUID `json:"id"`
	Created_At time.Time `json:"created_at"`
	Updated_At time.Time `json:"updated_at"`
	UserID     uuid.UUID `json:"user_id"`
}

// used to manage configuration for server
type apiConfig struct {
	fileServerHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
}

/*
	Main
*/

func main() {
	godotenv.Load()                      // load env vars
	dbURL := os.Getenv("DB_URL")         // fetch the db_url connection string
	jwtSecret := os.Getenv("JWT_SECRET") // fetch jwt secret
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
		jwtSecret:      jwtSecret,
	}

	// create a router (aka mux) for our project
	mux := http.NewServeMux()

	// create a new server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	mux.Handle("/app/", apiCfg.incrementFileServerHitsMiddleware((http.StripPrefix("/app", http.FileServer(http.Dir(filePathRoot))))))

	mux.HandleFunc("GET /admin/metrics", apiCfg.middlewareMetricsReport)
	mux.HandleFunc("POST /admin/reset", apiCfg.middlewareMetricsReset)

	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleTokenRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleTokenRevoke)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleGetChirpsById)
	mux.HandleFunc("GET /api/healthz", apiCfg.handleReportHealth)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetChirps)

	log.Printf("serving files from %s on port: %s\n", filePathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

// cleanBadWords replaces bad words with "****"
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

// sendJSONResponse sends a JSON response with a status code
func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// handleGetChirps returns all chirps sorted by created_at in ascending order
func (a *apiConfig) handleGetChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := a.db.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("error fetchign chirps %s", err)
	}

	chirpResponses := []ChirpResponse{}
	for _, chirp := range chirps {
		chirpResponses = append(chirpResponses, ChirpResponse{
			Id:         chirp.ID,
			Body:       chirp.Body,
			Created_At: chirp.CreatedAt,
			Updated_At: chirp.UpdatedAt,
			UserID:     chirp.UserID,
		})
	}

	sort.Slice(chirpResponses, func(i, j int) bool {
		return chirpResponses[i].Created_At.Before(chirpResponses[j].Created_At)
	})

	sendJSONResponse(w, 200, chirpResponses)
}

// handleGetChirpsById returns a single chirp passed in by id
func (a *apiConfig) handleGetChirpsById(w http.ResponseWriter, r *http.Request) {
	chirpId := r.PathValue("chirpID")

	var chirpResp ChirpResponse
	if chirpId == "" {
		chirpResp.Error = fmt.Sprintf("unable to find chirp id of %s please try again", chirpId)
		sendJSONResponse(w, 404, chirpResp)
		return
	}

	chirps, err := a.db.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("error fetching chirps %s", err)
	}

	for _, chirp := range chirps {
		if chirp.ID.String() == chirpId {
			chirpResp.Id = chirp.ID
			chirpResp.Body = chirp.Body
			chirpResp.Created_At = chirp.CreatedAt
			chirpResp.Updated_At = chirp.UpdatedAt
			chirpResp.UserID = chirp.UserID
		}
	}

	sendJSONResponse(w, 200, chirpResp)
}

// handleCreateUser creates a new user in the database
func (a *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var userReq req
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		log.Printf("Error decoding request: %s", err)
	}

	hashedPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		log.Printf("Error hashing password")
		return
	}

	userReq.Password = hashedPassword
	user, err := a.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          userReq.Email,
		HashedPassword: userReq.Password,
	})
	if err != nil {
		log.Printf("error creating user in database %s", err)
	}

	dbUser := User{
		ID:         user.ID,
		Created_At: user.CreatedAt,
		Updated_At: user.UpdatedAt,
		Email:      user.Email,
	}

	sendJSONResponse(w, http.StatusCreated, dbUser)
}

func (a *apiConfig) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	// fetch bearer token from header
	authToken, err := auth.GetBearerToken(w.Header())
	if err != nil {
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// find the token that matches our token in the database
	dbToken, err := a.db.GetTokenDetails(r.Context(), authToken)
	if err != nil {
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// update our database to revoke our token by setting the data to now and updated date to now
	a.db.RevokeToken(r.Context(), dbToken.Token)

}

// used to refresh our refresh token
func (a *apiConfig) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	// gets a refresh token from the header and find the user associated with the refresh token
	authToken, err := auth.GetBearerToken(w.Header())
	if err != nil {
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	fmt.Println("refresh token: ", authToken)
	// the sql query will only return a token if revoked = null and expired > now
	tokenDetails, err := a.db.GetTokenDetails(r.Context(), authToken)
	if err != nil {
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// create a new jwt
	returnToken, err := auth.MakeJWT(tokenDetails.UserID, a.jwtSecret, time.Duration(jwtTokenExiration))
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error creating new jwt"})
	}

	// return our jwt
	sendJSONResponse(w, 201, map[string]string{"token": returnToken})

}

// CheckValidityRefreshToken checks if the given refresh token is valid by
// verifying that it has not expired and has not been revoked.
func CheckValidityRefreshToken(tokenObj *database.RefreshToken) bool {
	notExpired := time.Now().Before(tokenObj.ExpiresAt)
	notRevoked := !tokenObj.RevokedAt.Valid

	return notExpired && notRevoked
}

// TODO: clean this up, the naming is all over the place
func (a *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	// struct for login request
	type loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var user loginRequest
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request payload"})
		return
	}

	users, err := a.db.GetAllUsers(r.Context())
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error retrieving users from db"})
		return
	}

	for _, dbUser := range users {
		if user.Email == dbUser.Email {
			if err := auth.CheckPasswordHash(user.Password, dbUser.HashedPassword); err != nil {
				sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unathorized bad password"})
				return
			}

			// create jwt token with 1 hour refresh
			jwtToken, err := auth.MakeJWT(dbUser.ID, a.jwtSecret, time.Duration(jwtTokenExiration)*time.Second)
			if err != nil {
				sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error generating token"})
			}

			// create refresh token with 1 hour refresh
			refreshToken, err := auth.MakeRefreshToken()
			if err != nil {
				sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error generating refresh token"})
			}

			// write the refresh token in the database
			a.db.CreateToken(r.Context(), database.CreateTokenParams{
				Token:  refreshToken,
				UserID: dbUser.ID,
			})

			// create the response and send it back in json form
			responseUser := User{
				ID:            dbUser.ID,
				Created_At:    dbUser.CreatedAt,
				Updated_At:    dbUser.UpdatedAt,
				Email:         dbUser.Email,
				Token:         jwtToken,
				Refresh_Token: refreshToken,
			}

			sendJSONResponse(w, http.StatusOK, responseUser)
			return
		}
	}

	// no user found
	sendJSONResponse(w, 401, map[string]string{"error": "no user found"})

}

// handleReportHealth responds with "OK" for health check
func (a *apiConfig) handleReportHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain;charset=utf-8")
	io.WriteString(w, "OK")
}

// handleCreateChirp processes the creation of a chirp
func (a *apiConfig) handleCreateChirp(w http.ResponseWriter, r *http.Request) {
	badWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	// look up token
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error reading token unauthorized")
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// fetch uuid from token
	fmt.Println("running validate jwt with:", token)
	fmt.Println("secret on server:", a.jwtSecret)
	userUUID, err := auth.ValidateJWT(token, a.jwtSecret)
	if err != nil {
		fmt.Println("error parsing with auth.ValidateJWT()", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var chirpReq ChirpRequest
	if err := json.NewDecoder(r.Body).Decode(&chirpReq); err != nil {
		log.Printf("Error decoding request: %s", err)
		sendJSONResponse(w, http.StatusInternalServerError, ChirpResponse{
			Error: "Failed to decode request body",
		})
		return
	}

	// if length is too large return error
	if len(chirpReq.Body) > 140 {
		log.Printf("Chirp body is too long: %d chars", len(chirpReq.Body))
		sendJSONResponse(w, http.StatusBadRequest, ChirpResponse{
			Error: "Chirp body exceeds 140 chars",
		})
		return
	}

	// clean the badwords
	chirpReq.Body = cleanBadWords(chirpReq.Body, badWords)
	fmt.Println("about to write to db for: ", userUUID.String())
	// write to database
	chirp, err := a.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   chirpReq.Body,
		UserID: userUUID,
	})
	if err != nil {
		log.Printf("error creating chirp in database %s", err)
	}

	chirpResponse := ChirpResponse{
		Body:       chirp.Body,
		Id:         chirp.ID,
		Created_At: chirp.CreatedAt,
		Updated_At: chirp.UpdatedAt,
		UserID:     chirp.UserID,
	}

	// send response
	sendJSONResponse(w, http.StatusCreated, chirpResponse)
}

// incrementFileServerHitsMiddleware increments the file server hits counter
func (a *apiConfig) incrementFileServerHitsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "no-cache")
		a.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// middlewareMetricsReport displays metrics in HTML format
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

// middlewareMetricsReset resets the file server hits and deletes users in dev mode
func (a *apiConfig) middlewareMetricsReset(w http.ResponseWriter, r *http.Request) {
	if a.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	a.db.DeleteAllUsers(r.Context())
	a.db.DeleteAllChirps(r.Context())
	a.db.DeleteAllTokens(r.Context())
	w.WriteHeader(http.StatusOK)
	a.fileServerHits.Store(0)
}
