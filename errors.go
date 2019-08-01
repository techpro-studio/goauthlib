package goauthlib

import "github.com/techpro-studio/gohttplib"

var entityAlreadyExists = gohttplib.HTTP403("ALREADY_EXISTS")
var entityHasAlreadyUser = gohttplib.HTTP403("HAS_ALREADY_USER")
var cantDeleteLastEntity = gohttplib.HTTP403("CANT_DELETE_LAST")
var invalidCode = gohttplib.HTTP403("INVALID_CODE")

var needFunctionName = gohttplib.HTTP400("Need function name")