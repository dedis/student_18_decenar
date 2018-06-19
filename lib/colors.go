package lib

import "github.com/fatih/color"

var YellowPrint func(format string, a ...interface{}) = color.New(color.FgYellow, color.Bold).PrintfFunc()
var GreenPrint func(format string, a ...interface{}) = color.New(color.FgGreen).PrintfFunc()
