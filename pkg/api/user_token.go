package api

import (
	"time"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/util"
	"github.com/ua-parser/uap-go/uaparser"
)

// GET /api/user/auth-tokens
func (server *HTTPServer) GetUserAuthTokens(c *models.ReqContext) Response {
	return server.getUserAuthTokensInternal(c, c.UserId)
}

// POST /api/user/revoke-auth-token
func (server *HTTPServer) RevokeUserAuthToken(c *models.ReqContext, cmd models.RevokeAuthTokenCmd) Response {
	return server.revokeUserAuthTokenInternal(c, c.UserId, cmd)
}

func (server *HTTPServer) logoutUserFromAllDevicesInternal(userID int64) Response {
	userQuery := models.GetUserByIdQuery{Id: userID}

	if err := bus.Dispatch(&userQuery); err != nil {
		if err == models.ErrUserNotFound {
			return Error(404, "User not found", err)
		}
		return Error(500, "Could not read user from database", err)
	}

	err := server.AuthTokenService.RevokeAllUserTokens(userID)
	if err != nil {
		return Error(500, "Failed to logout user", err)
	}

	return JSON(200, util.DynMap{
		"message": "User logged out",
	})
}

func (server *HTTPServer) getUserAuthTokensInternal(c *models.ReqContext, userID int64) Response {
	userQuery := models.GetUserByIdQuery{Id: userID}

	if err := bus.Dispatch(&userQuery); err != nil {
		if err == models.ErrUserNotFound {
			return Error(404, "User not found", err)
		}
		return Error(500, "Failed to get user", err)
	}

	tokens, err := server.AuthTokenService.GetUserTokens(userID)
	if err != nil {
		return Error(500, "Failed to get user auth tokens", err)
	}

	result := make([]*dtos.UserToken, len(tokens))
	for k, v := range tokens {
		isActive := false
		if c.UserToken != nil && c.UserToken.Id == v.Id {
			isActive = true
		}

		parser := uaparser.NewFromSaved()
		client := parser.Parse(v.UserAgent)

		result[k] = &dtos.UserToken{
			Id:              v.Id,
			IsActive:        isActive,
			ClientIp:        v.ClientIp,
			Device:          client.Device.ToString(),
			OperatingSystem: client.Os.Family,
			Browser:         client.UserAgent.Family,
			CreatedAt:       time.Unix(v.CreatedAt, 0),
			SeenAt:          time.Unix(v.SeenAt, 0),
		}
	}

	return JSON(200, result)
}

func (server *HTTPServer) revokeUserAuthTokenInternal(c *models.ReqContext, userID int64, cmd models.RevokeAuthTokenCmd) Response {
	userQuery := models.GetUserByIdQuery{Id: userID}

	if err := bus.Dispatch(&userQuery); err != nil {
		if err == models.ErrUserNotFound {
			return Error(404, "User not found", err)
		}
		return Error(500, "Failed to get user", err)
	}

	token, err := server.AuthTokenService.GetUserToken(userID, cmd.AuthTokenId)
	if err != nil {
		if err == models.ErrUserTokenNotFound {
			return Error(404, "User auth token not found", err)
		}
		return Error(500, "Failed to get user auth token", err)
	}

	if c.UserToken != nil && c.UserToken.Id == token.Id {
		return Error(400, "Cannot revoke active user auth token", nil)
	}

	err = server.AuthTokenService.RevokeToken(token)
	if err != nil {
		if err == models.ErrUserTokenNotFound {
			return Error(404, "User auth token not found", err)
		}
		return Error(500, "Failed to revoke user auth token", err)
	}

	return JSON(200, util.DynMap{
		"message": "User auth token revoked",
	})
}
