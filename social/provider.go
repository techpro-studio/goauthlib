package social

// ProviderResult is a result of authentication via social provider
type ProviderResult struct {
	ID    string
	Type  string
	Email string
	Phone string
	Raw   map[string]interface{}
}

//Provider is an fetcher through the social providers
type Provider interface {
	GetInfoByToken(token string) (*ProviderResult, error)
}
