package api

type CredentialResponse struct {
	Code int        `json:"code"`
	Msg  string     `json:"msg"`
	Data Credential `json:"data"`
}
type HttpResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}
