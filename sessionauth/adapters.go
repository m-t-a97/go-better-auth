package sessionauth

// This middleware uses only the Go standard library http.Handler interface
// and can be used with any framework that supports net/http handlers.
//
// Framework Integration Examples:
//
// Chi Router:
//    router := chi.NewRouter()
//    middleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
//    router.Use(middleware.Handler)
//    router.Post("/api/protected", middleware.Require(protectedHandler))
//
// Echo Framework:
//    e := echo.New()
//    middleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
//    e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
//        return func(c echo.Context) error {
//            middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//                c.Request = r.WithContext(c.Request().Context())
//                next(c)
//            })).ServeHTTP(c.Response(), c.Request())
//            return nil
//        }
//    })
//
// Gin Framework:
//    router := gin.New()
//    middleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
//    router.Use(func(c *gin.Context) {
//        middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//            c.Request = r
//            c.Next()
//        })).ServeHTTP(c.Writer, c.Request)
//    })
//
// Standard Library:
//    mux := http.NewServeMux()
//    middleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
//    mux.Use(middleware.Handler)  // Optional auth for all routes
//    mux.Handle("/api/protected", middleware.Require(protectedHandler))
//    http.ListenAndServe(":3000", mux)
