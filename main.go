package main

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	authnzab "penmanship/authnz/authboss"
	"regexp"
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
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	abclientstate "github.com/volatiletech/authboss-clientstate"
	"github.com/volatiletech/authboss/v3"
	_ "github.com/volatiletech/authboss/v3/auth"
	"github.com/volatiletech/authboss/v3/defaults"
	_ "github.com/volatiletech/authboss/v3/register"
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

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))

	ab, err := setupAuthBoss(db, r)
	if err != nil {
		log.Fatal(err)
	}

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authboss.Middleware2(ab, authboss.RequireNone, authboss.RespondUnauthorized))
		// TODO: Authz
	})

	CSRF := csrf.Protect(securecookie.GenerateRandomKey(32),
		csrf.Secure(env == "production"), csrf.CookieName("_csrf"))

	http.ListenAndServe(":1001", CSRF(r))
}

func setupAuthBoss(db *sql.DB, r *chi.Mux) (*authboss.Authboss, error) {
	// TODO
	// - If login or register fails, its a success response with details of an error
	//   Would rather go with unauthorized response
	// - With register, if database create fails then there is still a success response
	//   but the error is logged
	// - Need to load current user information for authz
	// - Improve validation
	generateRandomKey := func() string {
		return base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64))
	}

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(getEnvOrDefault("COOKIE_STORE_KEY", generateRandomKey()))
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(getEnvOrDefault("SESSION_STORE_KEY", generateRandomKey()))

	ab := authboss.New()
	database := authnzab.CreateStorer(db)

	ab.Config.Paths.Mount = "/"
	ab.Config.Paths.AuthLoginOK = "/"                     // TODO: Redirect to authz
	ab.Config.Paths.RegisterOK = "/"                      // TODO: Redirect to authz
	ab.Config.Paths.RootURL = "http://localhost:52112/"   // TODO: Env specific
	ab.Config.Core.ViewRenderer = defaults.JSONRenderer{} // TODO: Custom renderer

	cookieStore := abclientstate.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.HTTPOnly = true
	cookieStore.Secure = getEnvOrDefault("GO_ENV", "development") == "development"

	sessionStore := abclientstate.NewSessionStorer("penmanship", sessionStoreKey, nil)
	cstore := sessionStore.Store.(*sessions.CookieStore)
	cstore.Options.HttpOnly = true
	cstore.Options.Secure = getEnvOrDefault("GO_ENV", "development") == "development"
	cstore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	defaults.SetCore(&ab.Config, true, false)

	emailRule := defaults.Rules{
		FieldName:  "email",
		Required:   true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]+`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password",
		Required:  true,
		MinLength: 4,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		ReadJSON: true,
		Rulesets: map[string][]defaults.Rules{
			"login":    {emailRule, passwordRule},
			"register": {emailRule, passwordRule},
		},
	}

	// Initialize authboss (instantiate modules etc.)
	err := ab.Init()

	// Setup AuthBoss routes
	r.Use(ab.LoadClientStateMiddleware)

	r.Group(func(r chi.Router) {
		r.Use(authboss.ModuleListMiddleware(ab))
		r.Mount("/", ab.Config.Core.Router)
	})

	optionsHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-TOKEN", csrf.Token(r))
		w.WriteHeader(http.StatusOK)
	}
	r.MethodFunc("OPTIONS", "/*", optionsHandler)
	routes := []string{"login", "logout", "register"}
	for _, route := range routes {
		r.MethodFunc("OPTIONS", "/"+route, optionsHandler)
	}

	return ab, err
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
