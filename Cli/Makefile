.DEFAULT_GOAL := debug

DOTNET = dotnet
RUNTIME = linux-x64
TARGET = netcoreapp2.2
PACKER = ../Tools/linux-x64.warp-packer
EXEC_NAME = AttackSurfaceAnalyzerCli
PUBLISH_DIR = bin/Release/$(TARGET)/$(RUNTIME)/publish/
NBGV_DIR = ../Tools
VERSION := $(shell $(NBGV_DIR)/nbgv get-version -v AssemblyInformationalVersion)
FULL_EXEC_PATH = bin/$(EXEC_NAME)-linux-$(VERSION)

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
	dotnet build
	$(info Detected version as $(VERSION))

	$(DOTNET) publish -c Release -r $(RUNTIME) --self-contained true
	$(PACKER) --arch $(RUNTIME) --input_dir $(PUBLISH_DIR) --exec $(EXEC_NAME) --output $(FULL_EXEC_PATH)
	chmod +x $(FULL_EXEC_PATH)
	$(info Release build completed, result is located at $(FULL_EXEC_PATH))
