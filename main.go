package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	authnzab "penmanship/authnz/authboss"
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
	"github.com/volatiletech/authboss/v3"
)

func main() {
	env := getEnvOrDefault("GO_ENV", "development")

	connectionString, err := buildPgConnectionString(PgConnectionOptions{
		User:        getEnvOrDefault("POSTGRES_USER", ""),
		Password:    getEnvOrDefault("POSTGRES_PASSWORD", ""),
		Host:        getEnvOrDefault("POSTGRES_HOSTNAME", ""),
		Port:        getEnvOrDefault("POSTGRES_PORT", ""),
		SSLCert:     getEnvOrDefault("POSTGRES_SSLCERT", ""),
		SSLKey:      getEnvOrDefault("POSTGRES_SSLKEY", ""),
		SSLRootCert: getEnvOrDefault("POSTGRES_SSLROOTCERT", ""),
		SSLMode:     getEnvOrDefault("POSTGRES_SSLMODE", ""),
		Database:    getEnvOrDefault("POSTGRES_DB", "authnz"),
	})
	if err != nil {
		log.Fatal(err)
	}

	db := createDatabase(connectionString)
	driver := createDatabaseDriver(db)
	migration := createMigration(driver)

	err = migration.Up()
	if err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}

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

	setupAuthBoss(db)

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

func setupAuthBoss(db *sql.DB) error {
	// TODO
	authboss := authboss.New()
	database := authnzab.CreateStorer(db)

	authboss.Config.Storage.Server = database

	return nil
}

type PgConnectionOptions struct {
	User        string
	Password    string
	Host        string
	Port        string
	SSLCert     string
	SSLKey      string
	SSLRootCert string
	SSLMode     string
	Database    string
}

func buildPgConnectionString(options PgConnectionOptions) (string, error) {
	buildErrorMessage := func(field string) string {
		return fmt.Sprintf("empty pg connection option %s", field)
	}
	buildConnectionString := func(baseConnectionString string, queryParams url.Values) string {
		return fmt.Sprintf("%s?%s", baseConnectionString, queryParams.Encode())
	}

	if options.User == "" {
		return "", errors.New(buildErrorMessage("user"))
	} else if options.Password == "" {
		return "", errors.New(buildErrorMessage("password"))
	} else if options.Host == "" {
		return "", errors.New(buildErrorMessage("host"))
	} else if options.Port == "" {
		return "", errors.New(buildErrorMessage("port"))
	}

	baseConnectionString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s",
		options.User,
		options.Password,
		options.Host,
		options.Port,
		options.Database)

	if options.SSLMode == "disable" {
		sslOptions := struct {
			SSLMode string `url:"sslmode"`
		}{
			options.SSLMode,
		}

		v, _ := query.Values(sslOptions)

		return buildConnectionString(baseConnectionString, v), nil
	} else if options.SSLMode == "require" {
		if options.SSLCert == "" {
			return "", errors.New(buildErrorMessage("sslcert"))
		} else if options.SSLKey == "" {
			return "", errors.New(buildErrorMessage("sslkey"))
		}

		sslOptions := struct {
			SSLCert string `url:"sslcert"`
			SSLKey  string `url:"sslkey"`
			SSLMode string `url:"sslmode"`
		}{
			options.SSLCert,
			options.SSLKey,
			options.SSLMode,
		}

		v, _ := query.Values((sslOptions))

		return buildConnectionString(baseConnectionString, v), nil
	} else if options.SSLMode == "verify-ca" || options.SSLMode == "verify-full" {
		if options.SSLCert == "" {
			return "", errors.New(buildErrorMessage("sslcert"))
		} else if options.SSLKey == "" {
			return "", errors.New(buildErrorMessage("sslkey"))
		} else if options.SSLRootCert == "" {
			return "", errors.New(buildErrorMessage("sslrootcert"))
		}

		sslOptions := struct {
			SSLCert     string `url:"sslcert"`
			SSLKey      string `url:"sslkey"`
			SSLRootCert string `url:"sslrootcert"`
			SSLMode     string `url:"sslmode"`
		}{
			options.SSLCert,
			options.SSLKey,
			options.SSLRootCert,
			options.SSLMode,
		}

		v, _ := query.Values(sslOptions)

		return buildConnectionString(baseConnectionString, v), nil
	}

	return baseConnectionString, nil
}

func createDatabase(connectionString string) *sql.DB {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func createDatabaseDriver(db *sql.DB) database.Driver {
	driver, err := postgres.WithInstance(db, &postgres.Config{
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
