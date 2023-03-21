// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"test_iam/generated/swagger/models"
)

// LoginOKCode is the HTTP code returned for type LoginOK
const LoginOKCode int = 200

/*
LoginOK Success

swagger:response loginOK
*/
type LoginOK struct {

	/*
	  In: Body
	*/
	Payload *models.TokenPair `json:"body,omitempty"`
}

// NewLoginOK creates LoginOK with default headers values
func NewLoginOK() *LoginOK {

	return &LoginOK{}
}

// WithPayload adds the payload to the login o k response
func (o *LoginOK) WithPayload(payload *models.TokenPair) *LoginOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the login o k response
func (o *LoginOK) SetPayload(payload *models.TokenPair) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *LoginOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*
LoginDefault Unexpected error.

swagger:response loginDefault
*/
type LoginDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewLoginDefault creates LoginDefault with default headers values
func NewLoginDefault(code int) *LoginDefault {
	if code <= 0 {
		code = 500
	}

	return &LoginDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the login default response
func (o *LoginDefault) WithStatusCode(code int) *LoginDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the login default response
func (o *LoginDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the login default response
func (o *LoginDefault) WithPayload(payload *models.Error) *LoginDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the login default response
func (o *LoginDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *LoginDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
