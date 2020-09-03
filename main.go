package main

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	db      *gorm.DB
	dbAdmin *gorm.DB
	err1    error
	err2    error
	users   []User
)

func main() {

	dbAdmin, err1 = gorm.Open("sqlite3", "admin.db")
	db, err2 = gorm.Open("sqlite3", "user.db")
	if err1 != nil || err2 != nil {
		panic("failed to connect database")
	}

	dbAdmin.AutoMigrate(&User{})
	db.AutoMigrate(&User{})

	passw, _ := HashPassword("admin")
	db.Create(&User{Name: "admin", Age: 25, Role: "admin", Password: passw})
	db.Create(&User{Name: "John", Age: 25, Role: "user", Password: "password"})
	db.Create(&User{Name: "Muslim", Age: 27, Role: "user", Password: "password"})

	Routes()

	db.Close()
}
