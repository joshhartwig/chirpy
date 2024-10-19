# Notes for this project

This project is used for learning and nothing else. This is not production grade :). Just meant to further learn API development with Go.

# SQLC & Goose

This project leveraged both SQLC and Goose. Goose is a database migration tool that helps you apply changes to schemas. SQLC will convert SQL queries into type safe code. Neither of these tools is an ORM, you still need to write SQL.

## SQLC Notes

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

This should be the high level directory structure for your project

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
