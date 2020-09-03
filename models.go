package main

import "time"

var roleNumber map[string]int = map[string]int{
	"admin": 100,
	"user":  200,
}

type User struct {
	ID        uint       `gorm:"primary_key" json:"id"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `sql:"index" json:"-"`
	Name      string     `json:"name"`
	Age       int        `json:"age"`
	Role      string     `json:"role"`
	Password  string     `json:"-"`
}

type UserIn struct {
	ID        uint       `gorm:"primary_key" json:"-"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `sql:"index" json:"-"`
	Name      string     `json:"name"`
	Age       int        `json:"age"`
	Role      string     `json:"role"`
	Password  string     `json:"password"`
}

type ApproveUser struct {
	NewUser  UserIn `json:"new_user"`
	Approval string `json:"approval"`
}

type response struct {
	Users      []User `json:"users"`
	Message    string `json:"message"`
	StatusText string `json:"status_text"`
}
