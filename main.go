package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"penmanship/authnz/authn"
	"penmanship/authnz/authz"
	"penmanship/authnz/utils"
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
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	abclientstate "github.com/volatiletech/authboss-clientstate"
	"github.com/volatiletech/authboss/v3"
	_ "github.com/volatiletech/authboss/v3/auth"
	"github.com/volatiletech/authboss/v3/defaults"
	_ "github.com/volatiletech/authboss/v3/logout"
	_ "github.com/volatiletech/authboss/v3/register"
	"github.com/volatiletech/authboss/v3/remember"
)

func main() {
	env := utils.GetEnvOrDefault("GO_ENV", utils.Development)

	connectionString, err := buildPgConnectionString(PgConnectionOptions{
		User:        utils.GetEnvOrDefault("POSTGRES_USER", ""),
		Password:    utils.GetEnvOrDefault("POSTGRES_PASSWORD", ""),
		Host:        utils.GetEnvOrDefault("POSTGRES_HOSTNAME", ""),
		Port:        utils.GetEnvOrDefault("POSTGRES_PORT", ""),
		SSLCert:     utils.GetEnvOrDefault("POSTGRES_SSLCERT", ""),
		SSLKey:      utils.GetEnvOrDefault("POSTGRES_SSLKEY", ""),
		SSLRootCert: utils.GetEnvOrDefault("POSTGRES_SSLROOTCERT", ""),
		SSLMode:     utils.GetEnvOrDefault("POSTGRES_SSLMODE", ""),
		Database:    utils.GetEnvOrDefault("POSTGRES_DB", "authnz"),
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
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
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
		r.Get("/encryption", authz.Encryption)
	})

	// openssl rand -base64 32
	CSRF := csrf.Protect([]byte(utils.GetEnvOrDefault("CSRF_KEY", utils.GenerateRandomKey())),
		csrf.Secure(env == "production"), csrf.CookieName("_csrf"))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	http.ListenAndServe(":1001", CSRF(r))
}

func setupAuthBoss(db *sql.DB, r *chi.Mux) (*authboss.Authboss, error) {
	// TODO: Less than ideal but overriding default `Responder` and/or `ErrorHandler`
	// seems to have no effect, so we're stuck with 200 responses even if auth fails
	// Maybe another middleware can be attached after to override but don't think
	// it's necessary for the moment
	// See: https://github.com/volatiletech/authboss/issues/234

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(utils.GetEnvOrDefault("COOKIE_STORE_KEY", utils.GenerateRandomKey()))
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(utils.GetEnvOrDefault("SESSION_STORE_KEY", utils.GenerateRandomKey()))

	ab := authboss.New()
	database := authn.CreateStorer(db)

	ab.Config.Modules.LogoutMethod = "DELETE"
	ab.Config.Paths.Mount = "/"
	ab.Config.Paths.AuthLoginOK = "/"
	ab.Config.Paths.RegisterOK = "/"
	ab.Config.Paths.RootURL = utils.GetEnvOrDefault("AB_ROOTURL", "http://localhost:1001")
	ab.Config.Core.ViewRenderer = defaults.JSONRenderer{}

	cookieStore := abclientstate.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.HTTPOnly = true
	cookieStore.Secure = utils.GetEnvOrDefault("GO_ENV", utils.Development) == utils.Production

	sessionStore := abclientstate.NewSessionStorer("penmanship", sessionStoreKey, nil)
	cstore := sessionStore.Store.(*sessions.CookieStore)
	cstore.Options.HttpOnly = true
	cstore.Options.Secure = utils.GetEnvOrDefault("GO_ENV", utils.Development) == utils.Production
	cstore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	defaults.SetCore(&ab.Config, true, false)

	emailRule := defaults.Rules{
		FieldName:  "email",
		Required:   true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`/^([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/g`),
	}
	passwordRule := defaults.Rules{
		FieldName:       "password",
		Required:        true,
		MinLength:       8,
		MinLower:        1,
		MinUpper:        1,
		MinNumeric:      1,
		AllowWhitespace: false,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		ReadJSON: true,
		Rulesets: map[string][]defaults.Rules{
			"login":    {emailRule, passwordRule},
			"register": {emailRule, passwordRule},
		},
	}

	// Initialize authboss
	err := ab.Init()

	// Setup AuthBoss routes
	currentUserMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentUser, err := ab.LoadCurrentUser(&r)

			if err == nil {
				r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, currentUser))
			}

			handler.ServeHTTP(w, r)
		})
	}
	// NOTE: For remember middleware, the `rm` field has to be set on the login request
	// See: https://github.com/volatiletech/authboss-renderer/blob/b32bb7a1387f2ba930e691b841e786cb0be3ae28/html-templates/login.tpl#L6
	r.Use(ab.LoadClientStateMiddleware, remember.Middleware(ab), currentUserMiddleware)

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
		MigrationsTable:       utils.GetEnvOrDefault("POSTGRES_MIGRATIONS_TABLE", "migrations"),
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
