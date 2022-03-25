module github.com/AthenZ/k8s-athenz-sia

go 1.17

replace github.com/AthenZ/k8s-athenz-sia/pkg/identity => ./pkg/identity

require (
	github.com/AthenZ/athenz v1.10.51
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/pkg/errors v0.9.1
	github.com/yahoo/k8s-athenz-identity v0.0.0-20210320000321-b0ce39fad833
)

require (
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.1 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	golang.org/x/sys v0.0.0-20210831042530-f4d43177bf5e // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
)
