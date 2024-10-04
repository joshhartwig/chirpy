Notes for this project

#sqlc

Always run from the root of the project
cmd to install `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`
create sqlc.yaml

```yaml
#sqlc.yaml
version: "2"
sql:
  - schema: "sql/schema"
    queries: "sql/queries"
    engine: "postgresql"
    gen:
      go:
        out: "internal/database"
```

sqlc docs https://docs.sqlc.dev/en/latest/tutorials/getting-started-postgresql.html

store connection string in .env
go get `github.com/joho/godotenv`
```go
dbUrl := os.GetEnv("DB_URL")
```

SQL Open the connection
```go
db,err := sql.Open("postgres",dbUrl)
```


