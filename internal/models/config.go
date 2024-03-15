package models

type Config struct {
	Client   Client   `json:"client"`
	Database Database `json:"database"`
	Token    Token    `json:"token"`
	Email    Email    `json:"email"`
}

type Client struct {
	Domain string `json:"domain"`
}

type Database struct {
	User    string `json:"user"`
	Address string `json:"address"`
	Name    string `json:"name"`
}

type Token struct {
	RefreshExp int `json:"refreshExp"`
	AccessExp  int `json:"accessExp"`
}

type Email struct {
	Provider   string `json:"provider"`
	Sender     Sender `json:"sender"`
	HardVerify bool   `json:"hardVerify"`
}

type Sender struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}
