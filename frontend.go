package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"regexp"
)

type UserData struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type UserDataList struct {
	Resp     ResponseData `json:"resp"`
	UserList []UserData   `json:"user_list"`
}

type ResponseData struct {
	ErrStr string `json:"err_str"`
}

const BackendUrl = "http://localhost:9090"
const LoginPage = "./template/login.html"
const RegisterPage = "./template/register.html"
const IndexPage = "./template/index.html"
const PwdSalt = "rIc[@(}sgO>LNyAzaJ?k.RUhYOKZtQ#rlB+$r-e%rr*L-CF+33JTrg@}50E`X/50"
const SessionName = "auth-session-name"

func showPage(w http.ResponseWriter, data interface{}, pagePath string) {
	t, _ := template.ParseFiles(pagePath)
	_ = t.Execute(w, data)
}

func login(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	showPage(w, nil, LoginPage)
}

func hashPwd(username string, pwd string, salt string) string {
	s, _ := base64.StdEncoding.DecodeString(salt)
	pwdAdd := append([]byte(username+pwd), s...)
	h := sha256.New()
	h.Write(pwdAdd)
	result := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(result)
}

func loginPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	data := map[string]interface{}{}
	data["ErrStr"] = "Login error!"
	err = r.ParseForm()
	if err != nil {
		showPage(w, data, LoginPage)
		return
	}
	if len(r.Form["username"][0]) == 0 {
		data["ErrStr"] = "Username is empty!"
		showPage(w, data, LoginPage)
		return
	}
	if m, _ := regexp.MatchString("^[a-zA-Z0-9]+$", r.Form.Get("username")); !m {
		data["ErrStr"] = "Username is not alphanumeric!"
		showPage(w, data, LoginPage)
		return
	}
	username := r.Form["username"][0]
	password := r.Form["password"][0]
	log.Println("Username:", username, "Password:", password)
	passwordHash := hashPwd(username, password, PwdSalt)
	req := &UserData{
		Name:     "",
		Username: username,
		Email:    "",
		Password: passwordHash,
		Role:     "",
	}
	reqJson, _ := json.Marshal(req)
	log.Println(string(reqJson))

	request, err := http.NewRequest("POST", BackendUrl+"/login", bytes.NewBuffer(reqJson))
	if err != nil {
		showPage(w, data, LoginPage)
		return
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		showPage(w, data, LoginPage)
		return
	}
	defer response.Body.Close()

	resp := &UserDataList{}
	err = json.NewDecoder(response.Body).Decode(resp)
	log.Println(resp)
	if err != nil || resp.Resp.ErrStr != "success" {
		data["ErrStr"] = resp.Resp.ErrStr
		showPage(w, data, LoginPage)
		return
	}
	session, _ := store.New(r, SessionName)
	session.Values["username"] = resp.UserList[0].Username
	session.Values["role"] = resp.UserList[0].Role
	session.Values["email"] = resp.UserList[0].Email
	session.Values["name"] = resp.UserList[0].Name
	err = session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

func register(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	showPage(w, nil, RegisterPage)
}

func registerPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	data := map[string]interface{}{}
	data["ErrStr"] = "Registration error!"
	err = r.ParseForm()
	if err != nil {
		showPage(w, data, RegisterPage)
		return
	}
	name := r.Form["name"][0]
	username := r.Form["username"][0]
	password := r.Form["password"][0]
	email := r.Form["email"][0]
	role := r.Form["role"][0]
	log.Println("Name: ", name)
	log.Println("Username: ", username)
	log.Println("Password: ", password)
	log.Println("Email: ", email)
	log.Println("Role: ", role)
	passwordHash := hashPwd(username, password, PwdSalt)
	if len(username) <= 0 {
		data["ErrStr"] = "Username must not empty!"
		showPage(w, data, RegisterPage)
		return
	}
	if m, _ := regexp.MatchString("^[a-zA-Z0-9]+$", r.Form.Get("username")); !m {
		data["ErrStr"] = "Username is not alphanumeric!"
		showPage(w, data, RegisterPage)
		return
	}
	if m, _ := regexp.MatchString(`^([\w._]{2,10})@(\w+).([a-z]{2,4})$`, r.Form.Get("email")); !m {
		data["ErrStr"] = "Email format error!"
		showPage(w, data, RegisterPage)
		return
	}
	if role != "admin" && role != "user" {
		data["ErrStr"] = "Please check role account!"
		showPage(w, data, RegisterPage)
		return
	}

	req := &UserData{
		Name:     name,
		Username: username,
		Email:    email,
		Password: passwordHash,
		Role:     role,
	}
	reqJson, _ := json.Marshal(req)
	log.Println(string(reqJson))

	request, err := http.NewRequest("POST", BackendUrl+"/register", bytes.NewBuffer(reqJson))
	if err != nil {
		showPage(w, data, RegisterPage)
		return
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		showPage(w, data, RegisterPage)
		return
	}
	defer response.Body.Close()

	resp := &UserDataList{}
	err = json.NewDecoder(response.Body).Decode(resp)
	log.Println(resp)
	if err != nil || resp.Resp.ErrStr != "success" {
		data["ErrStr"] = resp.Resp.ErrStr
		showPage(w, data, RegisterPage)
		return
	}
	session, _ := store.New(r, SessionName)
	session.Values["username"] = resp.UserList[0].Username
	session.Values["role"] = resp.UserList[0].Role
	session.Values["email"] = resp.UserList[0].Email
	session.Values["name"] = resp.UserList[0].Name
	err = session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

func index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	req := &UserData{}
	reqJson, _ := json.Marshal(req)
	request, err := http.NewRequest("POST", BackendUrl+"/list", bytes.NewBuffer(reqJson))
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer response.Body.Close()
	resp := &UserDataList{}
	err = json.NewDecoder(response.Body).Decode(resp)
	if err != nil || resp.Resp.ErrStr != "success" {
		log.Println(err)
		http.Error(w, resp.Resp.ErrStr, http.StatusBadRequest)
		return
	}
	session, _ := store.Get(r, SessionName)
	usernameSession := session.Values["username"]
	if usernameSession == "" {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}
	isValidSession := false
	for _, userD := range resp.UserList {
		if reflect.DeepEqual(userD.Username, usernameSession) {
			isValidSession = true
			break
		}
	}
	if !isValidSession {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}
	t, err := template.ParseFiles(IndexPage)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = t.Execute(w, resp)
}

func logout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	session, _ := store.Get(r, SessionName)
	session.Values["username"] = ""
	session.Values["role"] = ""
	session.Values["email"] = ""
	session.Values["name"] = ""
	err := session.Save(r, w)
	if err != nil {
		log.Println(err)
	}
	http.Redirect(w, r, "/login", http.StatusMovedPermanently)
}

func edit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	usernameReq := ps.ByName("username")
	session, _ := store.Get(r, SessionName)
	usernameSession := session.Values["username"]
	roleSession := session.Values["role"]
	if roleSession != "admin" && usernameReq != usernameSession {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}
}

func editPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

func remove(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

var store *sessions.CookieStore

func init() {
	key := securecookie.GenerateRandomKey(32)
	keyUsed := hex.EncodeToString(key)
	log.Println("Key used:", keyUsed)
	store = sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		Domain:   "localhost:8080",
		Path:     "/",
		MaxAge:   3600 * 3, // 3 hours
		HttpOnly: true,
	}
}

func main() {
	router := httprouter.New()
	router.GET("/", index)
	router.GET("/login", login)
	router.POST("/login", loginPost)
	router.GET("/register", register)
	router.POST("/register", registerPost)
	router.GET("/logout", logout)
	router.GET("/edit/:username", edit)
	router.POST("/edit/:username", editPost)
	router.GET("/remove", remove)
	log.Fatal(http.ListenAndServe(":8080", router))
}
