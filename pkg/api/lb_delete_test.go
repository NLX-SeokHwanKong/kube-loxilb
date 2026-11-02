package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDeleteIfPresentContract(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		wantError bool
	}{
		{"success", 200, `{"result":"Success"}`, false},
		{"explicit missing rule", 404, `{"result":"no-rule error"}`, false},
		{"unknown API route", 404, `{"code":404,"message":"path not found"}`, true},
		{"other not found", 404, `{"result":"other missing resource"}`, true},
		{"forbidden", 403, `{"result":"no-rule error"}`, true},
		{"server failure", 503, `{"result":"no-rule error"}`, true},
		{"error in HTTP 200", 200, `{"result":"operation failed"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Error("unexpected method", r.Method)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			rest, err := NewRESTClient(base, "netlox", "v1", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client := &LoxiClient{RestClient: rest, Url: server.URL}
			model := &LoadBalancerModel{Service: LoadBalancerService{ExternalIP: "192.0.2.100", Port: 443, Protocol: "udp"}}
			if err := client.LoadBalancer().DeleteIfPresent(context.Background(), model); (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
			if tc.name == "explicit missing rule" {
				if err := client.LoadBalancer().Delete(context.Background(), model); err == nil {
					t.Fatal("legacy Delete changed its missing-rule behavior")
				}
			}
		})
	}
}
