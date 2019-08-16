package goauthlib

import "github.com/techpro-studio/gohttplib"

var entityAlreadyExists = gohttplib.NewServerError(403, "ALREADY_EXISTS", "Entity already exists", "codee", nil)
var entityHasAlreadyUser = gohttplib.NewServerError(403, "HAS_ALREADY_USER", "Entity has already user", "codee", nil)
var cantDeleteLastEntity = gohttplib.NewServerError(403, "CANT_DELETE_LAST", "Can't delete last entity", "codee", nil)
var invalidCode = gohttplib.NewServerError(403, "INVALID_CODE", "Invalid code", "codee", nil)
