package logging

import (
	"fmt"

	"go.uber.org/zap"
)

var (
	sugaredLogger *zap.SugaredLogger
)

func InitZapLogger(loggingMode string) {
	var (
		logger *zap.Logger
		err    error
	)
	if loggingMode == "development" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		panic(fmt.Sprintf("Cannot initialize logger: %v", err))
	}
	sugaredLogger = logger.Sugar()
}

func Logger() *zap.SugaredLogger {
	return sugaredLogger
}
