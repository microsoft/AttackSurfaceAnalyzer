.DEFAULT_GOAL := debug

DOTNET = dotnet
TARGET = netcoreapp2.2
EXEC_NAME = AttackSurfaceAnalyzerCli
TOOL_DIR = ../Tools
ELECTRON = $(TOOL_DIR)/electronize
CUSTOM_FEED = ../Tools/packages/
VERSION := $(shell $(TOOL_DIR)/nbgv get-version -v AssemblyInformationalVersion)
UNAME_S := $(shell uname -s)
ELECTRON_OUTPUT = bin/made/
PUBLISH_PATH = bin/AttackSurfaceAnalyzerGui

ifeq ($(OS),Windows_NT)
	RUNTIME = win
	ALT_RUNTIME = win
else
	ifeq ($(UNAME_S),Linux)
		RUNTIME = linux
		ALT_RUNTIME = linux
	endif
	ifeq ($(UNAME_S),Darwin)
		RUNTIME = osx
		ALT_RUNTIME = macos
	endif
endif


prerequisites:
	$(info Checking for nbgv, installing if required.)
	@which $(TOOL_DIR)/nbgv || dotnet tool install --tool-path $(TOOL_DIR)/ nbgv
	$(info Checking for electronNET.cli, installing if required.)

	@which $(TOOL_DIR)/electronize || dotnet tool install --tool-path $(TOOL_DIR)/ --version 0.0.11-custom --add-source $(CUSTOM_FEED) electronnet.cli 
	$(info Setting publish directory $(PUBLISH_DIR))

debug: prerequisites clean restore build_debug
release: prerequisites clean restore build_release

all: win win10 mac linux

win: RUNTIME = win
win: ALT_RUNTIME = win
win: prerequisites clean restore build_release

mac: RUNTIME = osx
mac: RUNTIME = macos
mac: build_release prerequisites clean restore build_release

linux: RUNTIME = linux
linux: RUNTIME = linux
linux: build_release prerequisites clean restore build_release

clean:
	$(info Cleaning...)
	dotnet clean

restore:
	$(info Restoring...)
	dotnet restore

build_debug:
	$(info Building debug...)
	$(ELECTRON) start
	$(info Debug build started.)

build_release:
	$(info Building $(RUNTIME) release at $(VERSION))
	mkdir -p $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION) && $(ELECTRON) build /target $(RUNTIME) /package-json package.json /relative-path $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)
	$(info Built release at $(ELECTRON_OUTPUT))