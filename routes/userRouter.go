package routes

import (
	"github.com/johndobsonUK/go-mongo-rest/controllers"
	"github.com/johndobsonUK/go-mongo-rest/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}