package graph

import (
	"music-auth/internal/auth"
	music "music-auth/music/service"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	AuthService  *auth.AuthService
	MusicService *music.MusicService
}
