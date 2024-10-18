package models

type ApiConfig struct {
	Domain   string
	Database Database
	Token    Token
	Email    Email
}

type Database struct {
	User     string
	Address  string
	Password string
}

type Token struct {
	RefreshExp int64
	AccessExp  int64
}

type Email struct {
	Provider   string
	Sender     Sender
	HardVerify bool
	ApiKey     string
}

type Sender struct {
	Address string
	Name    string
}
