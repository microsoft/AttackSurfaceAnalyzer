.DEFAULT_GOAL := debug

DOTNET = dotnet
TARGET = netcoreapp2.2
EXEC_NAME = AttackSurfaceAnalyzerCli
NBGV_DIR = ../Tools
VERSION := $(shell $(NBGV_DIR)/nbgv get-version -v AssemblyInformationalVersion | cut -d '-' -f 1)
UNAME_S := $(shell uname -s)
PUBLISH_PATH = bin/AsaCli

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

PUBLISH_DIR = "bin/AsaCli-$(ALT_RUNTIME)-$(VERSION)"

zipped: IS_ZIP = true
zipped: all
all: win win10 mac linux

prerequisites:
	$(info Checking for nbgv, installing if required.)
	@which $(NBGV_DIR)/nbgv || dotnet tool install --tool-path $(NBGV_DIR)/ nbgv
	$(info Setting publish directory $(PUBLISH_DIR))

debug: prerequisites clean restore build_debug
release: prerequisites clean restore build_release

win: RUNTIME = win-x86
win: ALT_RUNTIME = win
win: IS_WINDOWS = true
win: prerequisites clean restore build_release

win10: RUNTIME = win10-x64
win10: ALT_RUNTIME = win10
win10 IS_WINDOWS = true
win10: prerequisites clean restore build_release

mac: RUNTIME = osx-x64
mac: ALT_RUNTIME = macos
mac: prerequisites clean restore build_release

linux: RUNTIME = linux-x64
linux: ALT_RUNTIME = linux
linux: prerequisites clean restore build_release

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
	$(DOTNET) publish -c Release -r $(RUNTIME) --self-contained true --output $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)/res
	$(warning now we reached ifeq TEST=$(IS_WINDOWS))
ifeq ($(IS_WINDOWS),true)
	cp -f AsaLaunch.bat $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)/AsaLaunch.bat
else
	cp -f AsaLaunch.sh $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)/AsaLaunch.sh
endif
	cp -f ../filters.json $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)/filters.json
	$(info Release build completed)
ifeq ($(IS_ZIP),true)
	$(info Zipping up artifacts)
	zip -r9 $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION).zip $(PUBLISH_PATH)-$(ALT_RUNTIME)-$(VERSION)
endif

