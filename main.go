package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	//TODO: Take this from the env var or some config file
	connStr := "user=postgres port=5432 password=password dbname=email sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	emailDb := EmailDB{db: db}
	emailDb.Setup()

	t := time.Now()
	defer func(t time.Time) {
		elapsed := time.Now().Sub(t)
		log.Println("Time elapsed", elapsed)
	}(t)
	id := emailDb.NewEmail("test12", "password", 24)
	log.Println(id)
	log.Println(emailDb.VerifyEmail(id))
}

type EmailDB struct {
	db *sql.DB
}

// TODO: It takes a lot of time for crypt to generate and verify (20 to 50 ms!!!) the hash, how about turning it into a microservice
func (db EmailDB) Verify(username, password string) (present bool) {
	sql := `
	select password_hash = crypt($2, password_hash) from usernames where username = $1
	`

	res, err := db.db.Query(sql, username, password)
	if err != nil {
		fmt.Println(err)
	}

	for res.Next() {
		res.Scan(&present)
		return present
	}
	return false
}

// NOTE: Caller needs to verify that the email isn't present in the usernames table
// otherwise verify will fail even if this succeeds
func (db EmailDB) NewEmail(username, password string, hoursLimit int) (id string) {
	// TODO: Reserve Username in the usernames table??
	sql := `
	insert into unverified_usernames(username, password_hash, verifier_id, valid_till) values 
	($1, crypt($2, gen_salt('bf', 8)), encode(digest(now()::text, 'sha1'), 'hex'), now() + $3)
	returning verifier_id
	`
	// fmt sprintf because you cant do '$4 hours' directly into exec
	// XXX: Vuln to sql injection??
	res, err := db.db.Query(sql, username, password, fmt.Sprintf("'%d hours'", hoursLimit))
	if err != nil {
		log.Println("Error in creating new username: ", err)
		return ""
	}
	defer res.Close()

	for res.Next() {
		res.Scan(&id)
		return id
	}
	return "" // HOW IT REACHED HERE???
}

func (db EmailDB) VerifyEmail(id string) (success bool) {
	sql := `
	with info(username, password_hash) as (delete from unverified_usernames where verifier_id = $1 and now() < valid_till returning username, password_hash )
	insert into usernames(username, password_hash) select * from info
	`
	_, err := db.db.Exec(sql, id)
	if err != nil {
		log.Println("Error in verifying new username: ", err)
		return false
	}
	return true
}

func (db EmailDB) Setup() {
	sql := []string{
		"create extension if not exists pgcrypto",
		"create table if not exists usernames(username text, password_hash text, unique(username))",
		"create table if not exists unverified_usernames(username text, password_hash text, verifier_id text, valid_till date, unique(verifier_id), unique(username))",
	}
	for _, i := range sql {
		res, err := db.db.Query(i)
		if err != nil {
			log.Fatalf("%s\n %s", i, err)
		}
		res.Close()
	}
}
