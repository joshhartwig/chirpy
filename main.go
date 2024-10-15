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
	"github.com/joshhartwig/chirpy/internal/logger"

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

	mux.HandleFunc("PUT /api/users", apiCfg.handleUpdatePassword)

	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleTokenRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleTokenRevoke)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleGetChirpsById)
	mux.HandleFunc("GET /api/healthz", apiCfg.handleReportHealth)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetChirps)

	logger.InfoLogger.Printf("serving files from %s on port: %s\n", filePathRoot, port)
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
		logger.ErrorLogger.Printf("error fetching chirps %s", err)
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

// handleUpdatePassword allows a user to update a password via put request TODO: the logic on this is hokey at best
func (a *apiConfig) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {

	// the format our password change comes in
	type passwordChangeRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// fetch token from header
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		logAndRespond(w, http.StatusBadRequest, "error fetching token from header", err)
		return
	}
	// fetch the username from the token claim
	jwtUserUUID, err := auth.ValidateJWT(token, a.jwtSecret)
	if err != nil {
		logAndRespond(w, http.StatusUnauthorized, "error getting userid from jwt", err)
		return
	}

	// encode the response body into a struct
	var pwdChangeReq passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&pwdChangeReq); err != nil {
		logAndRespond(w, http.StatusInternalServerError, "error decoding json body", err)
		return
	}

	// fetch UUID from token and compare to UUID from db
	dbUserUUID, err := a.db.GetUserIDByToken(r.Context(), token)
	if jwtUserUUID != dbUserUUID {
		// the user ids are not the same
		logAndRespond(w, http.StatusUnauthorized, "the jwt userid and dbuserid does not match", err)
		return
	}
	// hash the passed in password
	hashedPwd, err := auth.HashPassword(pwdChangeReq.Password)
	if err != nil {
		logAndRespond(w, http.StatusInternalServerError, "error hashing password", err)
		return
	}

	a.db.UpdateUserPassword(r.Context(), database.UpdateUserPasswordParams{
		HashedPassword: hashedPwd,
		ID:             dbUserUUID,
	})

	resUser := User{
		ID:    dbUserUUID,
		Email: pwdChangeReq.Email,
	}

	sendJSONResponse(w, 200, resUser)
	// respond w/ 200 if success with updated user resource
}

// handleGetChirpsById returns a single chirp passed in by id
func (a *apiConfig) handleGetChirpsById(w http.ResponseWriter, r *http.Request) {
	chirpId := r.PathValue("chirpID")

	var chirpResp ChirpResponse
	if chirpId == "" {
		chirpResp.Error = fmt.Sprintf("unable to find chirp id of %s please try again", chirpId)
		logger.ErrorLogger.Printf("unabled to find chirpid of %s please try again", chirpId)
		sendJSONResponse(w, 404, chirpResp)
		return
	}

	chirps, err := a.db.GetAllChirps(r.Context())
	if err != nil {
		logger.ErrorLogger.Printf("error fetching chirps %s \n", err)
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
		logger.ErrorLogger.Printf("error decoding request %s \n", err)
	}

	hashedPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		logger.ErrorLogger.Printf("error hashing password %s \n", err)
		return
	}

	userReq.Password = hashedPassword
	user, err := a.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          userReq.Email,
		HashedPassword: userReq.Password,
	})
	if err != nil {
		logger.ErrorLogger.Printf("error creating user in database %s \n", err)
	}

	dbUser := User{
		ID:         user.ID,
		Created_At: user.CreatedAt,
		Updated_At: user.UpdatedAt,
		Email:      user.Email,
	}

	sendJSONResponse(w, http.StatusCreated, dbUser)
}

// fetches bearer token from headers, matches it in db and revokes the refresh token in database
func (a *apiConfig) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	// fetch bearer token from header
	authToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		logger.ErrorLogger.Printf("error getting bearer token %s \n", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized unable to find bearer token"})
		return
	}

	// find the token that matches our token in the database
	dbToken, err := a.db.GetTokenDetails(r.Context(), authToken)
	if err != nil {
		logger.ErrorLogger.Printf("error getting token details from database %s \n", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// update our database to revoke our token by setting the data to now and updated date to now
	a.db.RevokeToken(r.Context(), dbToken.Token)
	sendJSONResponse(w, http.StatusNoContent, map[string]string{"success": "revoked"})
}

// fetches bearer token from headers, verifies that refresh token is not revoked, sends new jwt
func (a *apiConfig) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	// gets a refresh token from the header and find the user associated with the refresh token
	authToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		logger.ErrorLogger.Printf("error getting bearer token %s \n", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized invalid getbearertoken"})
		return
	}

	fmt.Println("refresh token: ", authToken)
	// the sql query will only return a token if revoked = null and expired > now
	tokenDetails, err := a.db.GetTokenDetails(r.Context(), authToken)
	if err != nil {
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized gettokendetails"})
		return
	}

	// create a new jwt
	returnToken, err := auth.MakeJWT(tokenDetails.UserID, a.jwtSecret, time.Duration(jwtTokenExiration)*time.Second)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error creating new jwt"})
	}

	// return our jwt
	sendJSONResponse(w, http.StatusOK, map[string]string{"token": returnToken})

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

	// decode the json into the loginRequest struct
	var user loginRequest
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.ErrorLogger.Printf("error decoding json %s \n", err)
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request payload"})
		return
	}

	// fetch all our users from the db TODO: fix this to fetch one user
	users, err := a.db.GetAllUsers(r.Context())
	if err != nil {
		logger.ErrorLogger.Printf("error fetching database users %s \n", err)
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error retrieving users from db"})
		return
	}

	// find our user by email then check passwordHash
	for _, dbUser := range users {
		if user.Email == dbUser.Email {
			if err := auth.CheckPasswordHash(user.Password, dbUser.HashedPassword); err != nil {
				logger.ErrorLogger.Printf("error with password %s \n", err)
				sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unathorized bad password"})
				return
			}

			// create jwt token with 1 hour refresh
			jwtToken, err := auth.MakeJWT(dbUser.ID, a.jwtSecret, time.Duration(jwtTokenExiration)*time.Second)
			if err != nil {
				logger.ErrorLogger.Printf("error creating jwt %s \n", err)
				sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error generating token"})
				return
			}

			// create refresh token with 1 hour refresh
			refreshToken, err := auth.MakeRefreshToken()
			if err != nil {
				logger.ErrorLogger.Printf("error creating refresh token %s \n", err)
				sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error generating refresh token"})
				return
			}

			// write the refresh token in the database
			dbToken, err := a.db.CreateToken(r.Context(), database.CreateTokenParams{
				Token:  refreshToken,
				UserID: dbUser.ID,
			})

			if err != nil {
				logger.ErrorLogger.Printf("error creating token from db %s \n", err)
				sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "error creating dbtoken"})
				return
			}

			// create the response and send it back in json form
			responseUser := User{
				ID:            dbUser.ID,
				Created_At:    dbUser.CreatedAt,
				Updated_At:    dbUser.UpdatedAt,
				Email:         dbUser.Email,
				Token:         jwtToken,
				Refresh_Token: dbToken.Token,
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
		logger.ErrorLogger.Printf("error reading token unauthorized %s \n", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// fetch uuid from token
	fmt.Println("running validate jwt with:", token)
	fmt.Println("secret on server:", a.jwtSecret)
	userUUID, err := auth.ValidateJWT(token, a.jwtSecret)
	if err != nil {
		logger.ErrorLogger.Printf("error validating jwt %s \n", err)
		fmt.Println("error parsing with auth.ValidateJWT()", err)
		sendJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var chirpReq ChirpRequest
	if err := json.NewDecoder(r.Body).Decode(&chirpReq); err != nil {
		logger.ErrorLogger.Printf("error decoding json body %s \n", err)
		sendJSONResponse(w, http.StatusInternalServerError, ChirpResponse{
			Error: "Failed to decode request body",
		})
		return
	}

	// if length is too large return error
	if len(chirpReq.Body) > 140 {
		logAndRespond(w, http.StatusBadRequest, "chirp body is too long %d", fmt.Errorf("%d", len(chirpReq.Body)))
		return
	}

	// clean the badwords
	chirpReq.Body = cleanBadWords(chirpReq.Body, badWords)
	logger.InfoLogger.Printf("about to write to db for: %s \n", userUUID.String())
	// write to database
	chirp, err := a.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   chirpReq.Body,
		UserID: userUUID,
	})
	if err != nil {
		logger.ErrorLogger.Printf("error creating chirp in the database %s \n", err)
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

// Helper function for error logging and JSON response
func logAndRespond(w http.ResponseWriter, status int, message string, err error) {
	logger.ErrorLogger.Printf("%s: %s\n", message, err)
	sendJSONResponse(w, status, map[string]string{"error": message})
}
