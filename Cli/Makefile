.DEFAULT_GOAL := debug

DOTNET = dotnet
TARGET = netcoreapp2.2
EXEC_NAME = AttackSurfaceAnalyzerCli
NBGV_DIR = ../Tools
VERSION := $(shell $(NBGV_DIR)/nbgv get-version -v AssemblyInformationalVersion)
UNAME_S := $(shell uname -s)
PUBLISH_PATH = bin/AttackSurfaceAnalyzerCli-

ifeq ($(OS),Windows_NT)
	RUNTIME = win10-x64
	ALT_RUNTIME = win
else
	ifeq ($(UNAME_S),Linux)
		RUNTIME = linux-x64
		ALT_RUNTIME = linux
	endif
	ifeq ($(UNAME_S),Darwin)
		RUNTIME = osx-x64
		ALT_RUNTIME = macos
	endif
endif


prerequisites:
	$(info Checking for nbgv, installing if required.)
	@which $(NBGV_DIR)/nbgv || dotnet tool install --tool-path $(NBGV_DIR)/ nbgv
	$(info Setting publish directory $(PUBLISH_DIR))

debug: prerequisites clean restore build_debug
release: prerequisites clean restore build_release

all: win win10 mac linux

win: RUNTIME = win-x86
win: ALT_RUNTIME = win
win: prerequisites clean restore build_release

win10: RUNTIME = win10-x64
win10: ALT_RUNTIME = win10
win10: build_release prerequisites clean restore build_release

mac: RUNTIME = osx-x64
mac: ALT_RUNTIME = macos
mac: build_release prerequisites clean restore build_release

linux: RUNTIME = linux-x64
linux: ALT_RUNTIME = linux
linux: build_release prerequisites clean restore build_release

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
	$(info Building $(RUNTIME) release at $(VERSION))
	$(DOTNET) publish -c Release -r $(RUNTIME) --self-contained true --output $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)
	$(info Release build completed)

azure:
