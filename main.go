package main

import (
	"database/sql"
	"errors"
	"fmt"
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
	"github.com/google/go-querystring/query"
	"github.com/gorilla/csrf"
	_ "github.com/lib/pq"
)

func main() {
	env := getEnvOrDefault("GO_ENV", "development")

	connectionString, err := buildPgConnectionString(PgConnectionOptions{
		user:        getEnvOrDefault("POSTGRES_USER", ""),
		password:    getEnvOrDefault("POSTGRES_PASSWORD", ""),
		host:        getEnvOrDefault("POSTGRES_HOSTNAME", ""),
		port:        getEnvOrDefault("POSTGRES_PORT", ""),
		sslcert:     getEnvOrDefault("POSTGRES_SSLCERT", ""),
		sslkey:      getEnvOrDefault("POSTGRES_SSLKEY", ""),
		sslrootcert: getEnvOrDefault("POSTGRES_SSLROOTCERT", ""),
		sslmode:     getEnvOrDefault("POSTGRES_SSLMODE", ""),
	})
	if err != nil {
		log.Fatal(err)
	}

	driver := createDatabaseDriver(connectionString)
	migration := createMigration(driver)
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

type PgConnectionOptions struct {
	user        string
	password    string
	host        string
	port        string
	sslcert     string
	sslkey      string
	sslrootcert string
	sslmode     string
}

func buildPgConnectionString(options PgConnectionOptions) (string, error) {
	buildErrorMessage := func(field string) string {
		return fmt.Sprintf("empty pg connection option %s", field)
	}

	if options.user == "" {
		return "", errors.New(buildErrorMessage("user"))
	} else if options.password == "" {
		return "", errors.New(buildErrorMessage("password"))
	} else if options.host == "" {
		return "", errors.New(buildErrorMessage("host"))
	} else if options.port == "" {
		return "", errors.New(buildErrorMessage("port"))
	}

	baseConnectionString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s",
		options.user,
		options.password,
		options.host,
		options.port)

	if options.sslmode == "disable" {
		sslOptions := struct {
			SSLMode string `url:"sslmode"`
		}{
			options.sslmode,
		}

		v, _ := query.Values(sslOptions)

		return fmt.Sprintf("%s/?%s", baseConnectionString, v.Encode()), nil
	} else if options.sslmode == "require" {
		if options.sslcert == "" {
			return "", errors.New(buildErrorMessage("sslcert"))
		} else if options.sslkey == "" {
			return "", errors.New(buildErrorMessage("sslkey"))
		}

		sslOptions := struct {
			SSLCert string `url:"sslcert"`
			SSLKey  string `url:"sslkey"`
			SSLMode string `url:"sslmode"`
		}{
			options.sslcert,
			options.sslkey,
			options.sslmode,
		}

		v, _ := query.Values((sslOptions))

		return fmt.Sprintf("%s/?%s", baseConnectionString, v.Encode()), nil
	} else if options.sslmode == "verify-ca" || options.sslmode == "verify-full" {
		if options.sslcert == "" {
			return "", errors.New(buildErrorMessage("sslcert"))
		} else if options.sslkey == "" {
			return "", errors.New(buildErrorMessage("sslkey"))
		} else if options.sslrootcert == "" {
			return "", errors.New(buildErrorMessage("sslrootcert"))
		}

		sslOptions := struct {
			SSLCert     string `url:"sslcert"`
			SSLKey      string `url:"sslkey"`
			SSLRootCert string `url:"sslrootcert"`
			SSLMode     string `url:"sslmode"`
		}{
			options.sslcert,
			options.sslkey,
			options.sslrootcert,
			options.sslmode,
		}

		v, _ := query.Values(sslOptions)

		return fmt.Sprintf("%s/?%s", baseConnectionString, v.Encode()), nil
	}

	return baseConnectionString, nil
}

func createDatabaseDriver(connectionString string) database.Driver {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{
		DatabaseName:          getEnvOrDefault("POSTGRES_DB", "authnz"),
		MigrationsTable:       getEnvOrDefault("POSTGRES_MIGRATIONS_TABLE", "migrations"),
		MultiStatementEnabled: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	return driver
}

func createMigration(driver database.Driver) *migrate.Migrate {
	migration, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver)

	if err != nil {
		log.Fatal(err)
	}

	return migration
}

func getEnvOrDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)

	if !exists {
		value = defaultValue
	}

	return value
}
