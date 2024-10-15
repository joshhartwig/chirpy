# Notes for this project

# Setup

This guide provides instructions for setting up and using `sqlc` and `goose` in your project.

## sqlc

### Installation

Always run from the root of the project. Use the following command to install `sqlc`:

```sh
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### Configuration

Create a `sqlc.yaml` file with the following content:

```yaml
# sqlc.yaml
version: "2"
sql:
  - schema: "sql/schema"
    queries: "sql/queries"
    engine: "postgresql"
    gen:
      go:
        out: "internal/database"
```

For more details, refer to the [sqlc documentation](https://docs.sqlc.dev/en/latest/tutorials/getting-started-postgresql.html).

### Environment Setup

Store the connection string in a `.env` file. Install the `godotenv` package:

```sh
go get github.com/joho/godotenv
```

Load the environment variable in your Go code:

```go
dbUrl := os.Getenv("DB_URL")
```

### Database Connection

Open the SQL connection using the following code:

```go
db, err := sql.Open("postgres", dbUrl)
if err != nil {
    log.Fatal(err)
}
```

## Goose

### Workflow

1. Add the new `.sql` file in the `schema` directory.
2. Run command from db/schema directory
`goose -dir sql/schema postgres "postgres://joshuahartwig:@localhost:5432/chirpy" up`
3. Run `sqlc generate` from root of project to generate the Go code.

should have this dir structure
```yaml
project-root/
├── sql/
│   ├── schema/
│   │   ├── 001_users.sql
│   │   ├── 002_create_chirps_table.sql
│   ├── queries/
│   │   ├── users.sql
│   │   ├── chirps.sql
├── internal/
│   ├── database/
│   │   ├── (generated Go files)
├── sqlc.yaml
```

Generate random string `openssl rand -base64 64`

### Course Notes for Boot.Dev Building Webservers In Go

Chapter 6 Section 11 is somewhat confusing and should be implemented like so

1. POST /api/users => Creates a user but does not return a jwt or refresh token (maybe it should so you dont need to login)
2. POST /api/login => With the correct username and password the user is provided a jwt and refresh token, the jwt expires in 1 hour the refresh token expires in 60 days
3. POST /api/refresh => This expects a refresh token, it verifies the refresh token matches the token in the database with the one passed into the headers. If those match, it will send a new jwt
4. POST /api/revoke => This will revoke a refresh token in the database