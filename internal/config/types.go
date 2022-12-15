package config

type FuzzTestType string

const (
	CPP    FuzzTestType = "cpp"
	JAVA   FuzzTestType = "java"
	KOTLIN FuzzTestType = "kotlin"
)

type Engine string

const (
	LIBFUZZER Engine = "libfuzzer"
)
