// Code generated by https://github.com/gagliardetto. DO NOT EDIT.

package main

import "clevergo.tech/clevergo"

// Package clevergo.tech/clevergo@v0.5.2
func UntrustedSources_ClevergoTechClevergoV052() {
	// Untrusted flow sources from method calls.
	{
		// Untrusted flow sources from method calls on clevergo.tech/clevergo.Context.
		{
			// func (*Context).BasicAuth() (username string, password string, ok bool)
			{
				var receiverContext656 clevergo.Context
				resultUsername414, resultPassword518, _ := receiverContext656.BasicAuth()
				sink(
					resultUsername414, // $untrustedFlowSource
					resultPassword518, // $untrustedFlowSource
				)
			}
			// func (*Context).Decode(v interface{}) (err error)
			{
				var receiverContext650 clevergo.Context
				var paramV784 interface{}
				receiverContext650.Decode(paramV784)
				sink(paramV784) // $untrustedFlowSource
			}
			// func (*Context).DefaultQuery(key string, defaultVlue string) string
			{
				var receiverContext957 clevergo.Context
				result520 := receiverContext957.DefaultQuery("", "")
				sink(result520) // $untrustedFlowSource
			}
			// func (*Context).FormValue(key string) string
			{
				var receiverContext443 clevergo.Context
				result127 := receiverContext443.FormValue("")
				sink(result127) // $untrustedFlowSource
			}
			// func (*Context).GetHeader(name string) string
			{
				var receiverContext483 clevergo.Context
				result989 := receiverContext483.GetHeader("")
				sink(result989) // $untrustedFlowSource
			}
			// func (*Context).PostFormValue(key string) string
			{
				var receiverContext982 clevergo.Context
				result417 := receiverContext982.PostFormValue("")
				sink(result417) // $untrustedFlowSource
			}
			// func (*Context).QueryParam(key string) string
			{
				var receiverContext584 clevergo.Context
				result991 := receiverContext584.QueryParam("")
				sink(result991) // $untrustedFlowSource
			}
			// func (*Context).QueryParams() net/url.Values
			{
				var receiverContext881 clevergo.Context
				result186 := receiverContext881.QueryParams()
				sink(result186) // $untrustedFlowSource
			}
			// func (*Context).QueryString() string
			{
				var receiverContext284 clevergo.Context
				result908 := receiverContext284.QueryString()
				sink(result908) // $untrustedFlowSource
			}
		}
		// Untrusted flow sources from method calls on clevergo.tech/clevergo.Params.
		{
			// func (Params).String(name string) string
			{
				var receiverParams137 clevergo.Params
				result494 := receiverParams137.String("")
				sink(result494) // $untrustedFlowSource
			}
		}
	}
	// Untrusted flow sources from interface method calls.
	{
		// Untrusted flow sources from method calls on clevergo.tech/clevergo.Decoder interface.
		{
			// func (Decoder).Decode(req *net/http.Request, v interface{}) error
			{
				var receiverDecoder873 clevergo.Decoder
				var paramV599 interface{}
				receiverDecoder873.Decode(nil, paramV599)
				sink(paramV599) // $untrustedFlowSource
			}
		}
	}
	// Untrusted flow sources from struct fields.
	{
		// Untrusted flow sources from clevergo.tech/clevergo.Context struct fields.
		{
			structContext409 := new(clevergo.Context)
			sink(structContext409.Params) // $untrustedFlowSource
		}
		// Untrusted flow sources from clevergo.tech/clevergo.Param struct fields.
		{
			structParam246 := new(clevergo.Param)
			sink(
				structParam246.Key,   // $untrustedFlowSource
				structParam246.Value, // $untrustedFlowSource
			)
		}
	}
	// Untrusted flow sources from types.
	{
		{
			var typeParams898 clevergo.Params
			sink(typeParams898) // $untrustedFlowSource
		}
	}
}
