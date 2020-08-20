package main

import (
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type User struct {
	ID        uint       `gorm:"primary_key" json:"id"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `sql:"index" json:"-"`
	Name      string     `json:"name"`
	Age       int        `json:"age"`
	IsAdmin   bool       `json:"is_admin"`
	Password  string     `json:"-"`
}

type UserIn struct {
	ID        uint       `gorm:"primary_key" json:"-"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `sql:"index" json:"-"`
	Name      string     `json:"name"`
	Age       int        `json:"age"`
	IsAdmin   bool       `json:"is_admin"`
	Password  string     `json:"password"`
}

var (
	db    *gorm.DB
	err   error
	users []User
)

func main() {

	db, err = gorm.Open("sqlite3", "test.db")
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{})

	db.Create(&User{Name: "John", Age: 25, IsAdmin: true, Password: "password"})
	db.Create(&User{Name: "Muslim", Age: 27, IsAdmin: false, Password: "password"})

	Routes()

	db.Close()
}
