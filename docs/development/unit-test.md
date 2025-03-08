# Unit Test

Prefer to use [onsi/gomega: Ginkgo's Preferred Matcher Library](https://github.com/onsi/gomega) as the assertion library.

## Wrap test with gomega

```go
// dot import gomega library to use methods directly with package name
import . "github.com/onsi/gomega"

// ...

  // update the assertion in the test loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			if tt.before != nil {
				tt.args = tt.before(g, tt.args)
			}

			// execute the target method of the unit test
			err := TargetMethod(tt.args.A, tt.args.B)

			if tt.after != nil {
				defer tt.after()
			}
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.want == nil {
				g.Expect(got).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
  }
```

## Test with ghttp

```go
	// add before and after function for setup and teardown the test server
	type test struct {
		// ...
		before  func(*WithT, args) args
		after   func()
	}
  // define before and after function in each test cases
	tests := []test{
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			responseBody := interface{}

			return test{
				name: "Test with ghttp server sample",
				// ...
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("GET", "/test/path"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
	}
```
