package handlers

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"test_iam/generated/swagger/models"
	"test_iam/generated/swagger/restapi/operations/user"
)

func UserRoles() user.GetUserRolesHandlerFunc {
	return func(params user.GetUserRolesParams, auth interface{}) middleware.Responder {
		_, ok := auth.(*models.Principal)
		if !ok {
			return user.NewGetUserRolesDefault(http.StatusInternalServerError).WithStatusCode(http.StatusInternalServerError)
		}

		return user.NewGetUserRolesOK().WithPayload([]string{"all ok"})
	}
}
