package dtos

import "time"

type UserToken struct {
	Id              int64     `json:"id"`
	IsActive        bool      `json:"isActive"`
	ClientIp        string    `json:"clientIp"`
	Device          string    `json:"device"`
	OperatingSystem string    `json:"os"`
	Browser         string    `json:"browser"`
	CreatedAt       time.Time `json:"createdAt"`
	SeenAt          time.Time `json:"seenAt"`
}
