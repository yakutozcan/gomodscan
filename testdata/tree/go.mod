module example.com/root

go 1.24.0

toolchain go1.24.1

require (
 example.com/shared v1.2.0
 example.com/transitive v0.1.0 // indirect
)
replace example.com/transitive => ../local
exclude example.com/shared v1.1.0
retract [v0.1.0, v0.2.0] // broken releases
tool example.com/shared/cmd/tool
