package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/gorilla/csrf"
	_ "github.com/lib/pq"
)

func main() {
	env := getEnv("GO_ENV", "development")

	driver := getDatabaseDriver()
	migration := getMigration(driver)
	migration.Up()

	r := chi.NewRouter()

	r.Use(middleware.RedirectSlashes)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.AllowContentType("application/json"))
	r.Use(middleware.Compress(5))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: false,
	}))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root."))
	})

	// TODO: CSRF stuff needs updating
	// - Auth key
	// - https://github.com/gorilla/csrf#javascript-applications
	csrf.Secure(env == "production")
	CSRF := csrf.Protect([]byte("32-byte-long-auth-key"))

	http.ListenAndServe(":1001", CSRF(r))
}

func getDatabaseDriver() database.Driver {
	// TODO: SSH access
	db, err := sql.Open("postgres", getEnv("CONNECTION_STRING", "postgres://postgres:postgres@localhost:5432/?sslmode=disable"))
	if err != nil {
		log.Fatal(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{
		DatabaseName:          getEnv("POSTGRES_DB", "authnz"),
		MigrationsTable:       getEnv("POSTGRES_MIGRATIONS_TABLE", "migrations"),
		MultiStatementEnabled: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	return driver
}

func getMigration(driver database.Driver) *migrate.Migrate {
	migration, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver)

	if err != nil {
		log.Fatal(err)
	}

	return migration
}

func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)

	if !exists {
		value = defaultValue
	}

	return value
}
