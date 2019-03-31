.DEFAULT_GOAL := debug

DOTNET = dotnet
TARGET = netcoreapp2.2
EXEC_NAME = AttackSurfaceAnalyzerCli
NBGV_DIR = ../Tools
VERSION := $(shell $(NBGV_DIR)/nbgv get-version -v AssemblyInformationalVersion)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	RUNTIME = linux-x64
	ALT_RUNTIME = linux-x64
endif
ifeq ($(UNAME_S),Darwin)
	RUNTIME = osx-x64
	ALT_RUNTIME = macos-x64
endif
PUBLISH_DIR = bin/AttackSurfaceAnalyzerCli-$(ALT_RUNTIME)-$(VERSION)

prerequisites:
	$(info Checking for nbgv, installing if required.)
	@which $(NBGV_DIR)/nbgv || dotnet tool install --tool-path $(NBGV_DIR)/ nbgv

all: prerequisites debug
debug: prerequisites clean restore build_debug
release: prerequisites clean restore build_release

clean:
	$(info Cleaning...)
	dotnet clean

restore:
	$(info Restoring...)
	dotnet restore

build_debug:
	$(info Building debug...)
	dotnet build
	$(info Debug build completed.)

build_release:
	$(info Building release...)
	$(info Detected version as $(VERSION))

	$(DOTNET) publish -c Release -r $(RUNTIME) --self-contained true --output $(PUBLISH_DIR)
	$(info Release build completed)