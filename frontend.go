package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"log"
	"net/http"
	"regexp"
)

type UserData struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserDataList struct {
	Resp     ResponseData `json:"resp"`
	UserList []UserData   `json:"user_list"`
}

type ResponseData struct {
	ErrStr string `json:"err_str"`
}

const FrontEndUrl = "http://localhost:8080"
const BackendUrl = "http://localhost:9090"
const LoginPage = "./template/login.html"
const RegisterPage = "./template/register.html"
const IndexPage = "./template/index.html"
const PwdSalt = "rIc[@(}sgO>LNyAzaJ?k.RUhYOKZtQ#rlB+$r-e%rr*L-CF+33JTrg@}50E`X/50"

func showPage(w http.ResponseWriter, errStr string, pagePath string) {
	log.Println(errStr)
	resp := &ResponseData{ErrStr: errStr}
	t, _ := template.ParseFiles(pagePath)
	_ = t.Execute(w, resp)
}

func login(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	showPage(w, "", LoginPage)
}

func hashPwd(pwd string, salt string) string {
	s, _ := base64.StdEncoding.DecodeString(salt)
	pwdAdd := append([]byte(pwd), s...)
	h := sha256.New()
	h.Write(pwdAdd)
	result := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(result)
}

func loginPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	err = r.ParseForm()
	if err != nil {
		showPage(w, "Login failed", LoginPage)
		return
	}
	if len(r.Form["username"][0]) == 0 {
		showPage(w, "Username is empty!", LoginPage)
		return
	}
	if m, _ := regexp.MatchString("^[a-zA-Z]+$", r.Form.Get("username")); !m {
		showPage(w, "Username is not alphanumeric", LoginPage)
		return
	}

	username := r.Form["username"][0]
	password := r.Form["password"][0]
	log.Println("Username:", username, "Password:", password)
	passwordHash := hashPwd(password, PwdSalt)
	req := &UserData{
		Name:     "",
		Username: username,
		Email:    "",
		Password: passwordHash,
	}
	reqJson, _ := json.Marshal(req)
	log.Println(string(reqJson))

	request, err := http.NewRequest("POST", BackendUrl+"/login", bytes.NewBuffer(reqJson))
	if err != nil {
		showPage(w, "Login failed", LoginPage)
		return
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		showPage(w, "Login failed", LoginPage)
		return
	}
	defer response.Body.Close()

	resp := &ResponseData{}
	err = json.NewDecoder(response.Body).Decode(resp)
	if err != nil || resp.ErrStr != "success" {
		showPage(w, "Login error", LoginPage)
		return
	}
	//showPage(w, "Login success", LoginPage)
	http.Redirect(w, r, FrontEndUrl, http.StatusMovedPermanently)
}

func register(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	showPage(w, "", RegisterPage)
}

func registerPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	err = r.ParseForm()
	if err != nil {
		showPage(w, "Registration failed", RegisterPage)
		return
	}
	if len(r.Form["username"][0]) == 0 {
		showPage(w, "Username is empty", RegisterPage)
		return
	}
	if m, _ := regexp.MatchString("^[a-zA-Z]+$", r.Form.Get("username")); !m {
		showPage(w, "Username is not alphanumeric", RegisterPage)
		return
	}
	if m, _ := regexp.MatchString(`^([\w._]{2,10})@(\w+).([a-z]{2,4})$`, r.Form.Get("email")); !m {
		showPage(w, "Email format error", RegisterPage)
		return
	}
	name := r.Form["name"][0]
	username := r.Form["username"][0]
	password := r.Form["password"][0]
	email := r.Form["email"][0]
	log.Println("Name: ", name)
	log.Println("Username: ", username)
	log.Println("Password: ", password)
	log.Println("Email: ", email)
	passwordHash := hashPwd(password, PwdSalt)

	req := &UserData{
		Name:     name,
		Username: username,
		Email:    email,
		Password: passwordHash,
	}
	reqJson, _ := json.Marshal(req)
	log.Println(string(reqJson))

	request, err := http.NewRequest("POST", BackendUrl+"/register", bytes.NewBuffer(reqJson))
	if err != nil {
		showPage(w, "Registration failed", RegisterPage)
		return
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		showPage(w, "Registration failed", RegisterPage)
		return
	}
	defer response.Body.Close()

	resp := &ResponseData{}
	err = json.NewDecoder(response.Body).Decode(resp)
	if err != nil || resp.ErrStr != "success" {
		showPage(w, "Registration failed", RegisterPage)
		return
	}
	//showPage(w, "Registration success", RegisterPage)
	http.Redirect(w, r, FrontEndUrl, http.StatusMovedPermanently)
}

func index(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := template.ParseFiles(IndexPage)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = t.Execute(w, resp)
}

func main() {
	router := httprouter.New()
	router.GET("/", index)
	router.GET("/login", login)
	router.POST("/login", loginPost)
	router.GET("/register", register)
	router.POST("/register", registerPost)
	log.Fatal(http.ListenAndServe(":8080", router))
}
