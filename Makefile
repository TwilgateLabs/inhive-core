.ONESHELL:
PRODUCT_NAME=inhive-core
BASENAME=$(PRODUCT_NAME)
BINDIR=bin
LIBNAME=$(PRODUCT_NAME)
CLINAME=InhiveCli

BRANCH=$(shell git branch --show-current)
# 2>/dev/null + single-word fallback: старое "unknown version" содержало ПРОБЕЛ и,
# попав в -ldflags, разорвало бы флаг на два аргумента. Версия идёт в -X, поэтому
# она обязана быть одним словом при любом исходе git describe.
VERSION=$(shell git describe --tags 2>/dev/null || echo "unknown")
ifeq ($(OS),Windows_NT)
Not available for Windows! use bash in WSL
endif
CRONET_GO_VERSION := $(shell cat sing-box/.github/CRONET_GO_VERSION)
# BASE_TAGS — общие для всех платформ, включая iOS. with_naive_outbound на ВСЕХ:
# naive (Cloudflare-mimicking HTTPS через статический libcronet.a) — наш
# сильнейший анти-DPI fallback в РФ; работает на iOS с build 44 (CGO static
# link, feedback_build_ios_cronet_purego). Cronet mmap'ится on-demand, 50MB
# NE-бюджет держится (эмпирически build 44→72). Кратковременный выпил из iOS
# (2026-07-02 аудит) был ошибкой: риск jetsam теоретический, а сам jetsam уже
# закрыт dial-cap 256 + thread-cap 512 + mem-ceiling 32MB. Возврат 2026-07-04.
BASE_TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0,with_olcrtc,with_naive_outbound
TAGS=$(BASE_TAGS)
IOS_TAGS=$(BASE_TAGS)
# with_dhcp убран из iOS-тагов (2026-07-02): DHCP-DNS discovery в iOS NE не
# работает (нет доступа к DHCP-опциям интерфейса), наш конфиг-билдер dhcp://
# сам не эмитит, а dhcp://-сервер из чужого конфига получит понятную ошибку
# стаба вместо тихо неработающего резолвера.
IOS_ADD_TAGS=with_low_memory
MACOS_ADD_TAGS=with_dhcp
# make ios IOS_TARGET=ios — device-only сборка (без симуляторного слайса:
# он ~241MB из 362MB xcframework и удваивает время сборки).
IOS_TARGET ?= ios,iossimulator
WINDOWS_ADD_TAGS=with_purego
# VERSION_LDFLAGS — почему обе -X обязательны в КАЖДОМ артефакте:
#
#   constant.Version — в исходнике объявлен как `var Version = "unknown"`
#   (sing-box/constant/version.go). Без -X он таким и остаётся в бинаре, и это
#   не косметика: clashapi отдаёт "sing-box unknown" (experimental/clashapi/
#   server.go:434), libbox.Version() тоже (experimental/libbox/setup.go:70), а
#   experimental/deprecated/constants.go:27 делает semver.IsValid("v"+Version)
#   → на "unknown" всегда false → Impending() всегда false → предупреждения о
#   deprecated-опциях конфига НИКОГДА не показываются пользователю. То есть по
#   баг-репорту нельзя определить сборку, и о ломающих изменениях конфига мы
#   молчим.
#
#   internal/godebug.defaultGODEBUG=multipathtcp=0 — Go 1.24+ включает MPTCP для
#   Dial по умолчанию. Для прокси это лишний вектор фингерпринтинга и источник
#   расхождений на сетях, где MPTCP-опции режут middlebox'ы. Апстрим гасит его
#   во всех своих сборках (sing-box/Makefile:9, cmd/internal/build_libbox/
#   main.go:63-64, .github/workflows/*.yml) — мы обязаны совпадать, иначе наш
#   форк ведёт себя иначе, чем протестированный апстримом код.
#
# Раньше здесь стоял $${CODE_VERSION} — раскрывался в shell-переменную
# ${CODE_VERSION}, которую НИКТО никогда не выставлял (grep по репозиторию даёт
# ровно одно вхождение — это самое). Мёртвая подстановка в пустую строку.
#
#   Версий ДВЕ, и обе объявлены как "unknown":
#     sing-box/constant.Version                    — апстримная (clashapi, libbox)
#     v2/hcommon/constants.Version                 — наша, инхайвовская
#   Вторая сегодня читается только в cmd/cmd_version.go ("inhive-core version
#   <...> sing-box version <...>"), но проставлять надо обе: иначе `InhiveCli
#   version` рапортует "unknown" ровно там, куда смотрят при разборе инцидента.
VERSION_LDFLAGS=-X github.com/sagernet/sing-box/constant.Version=$(VERSION) -X github.com/twilgate/inhive-core/v2/hcommon/constants.Version=$(VERSION) -X internal/godebug.defaultGODEBUG=multipathtcp=0
LDFLAGS=-w -s -checklinkname=0 -buildid= $(VERSION_LDFLAGS)
GOBUILDLIB=CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -buildmode=c-shared
GOBUILDSRV=CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS)

CRONET_DIR=./cronet
.PHONY: protos
protos:
	go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	# protoc --go_out=./ --go-grpc_out=./ --proto_path=inhiverpc inhiverpc/*.proto
	# for f in $(shell find v2 -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	# for f in $(shell find extension -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	protoc --doc_out=./docs  --doc_opt=markdown,inhiverpc.md $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# protoc --js_out=import_style=commonjs,binary:./extension/html/rpc/ --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./extension/html/rpc/ $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# npx browserify extension/html/rpc/extension.js >extension/html/rpc.js


lib_install: prepare
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.12
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.12
	npm install

headers:
	go build -buildmode=c-archive -o $(BINDIR)/ ./platform/desktop2

android: lib_install
	CGO_LDFLAGS="-O2 -s -w -Wl,-z,max-page-size=16384" \
	gomobile bind -v \
		-androidapi=24 \
		-javapkg=com.inhive.core \
		-libname=inhive-core \
		-tags=$(TAGS) \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-target=android/arm,android/arm64,android/amd64 \
		-o $(BINDIR)/$(LIBNAME).aar \
		github.com/sagernet/sing-box/experimental/libbox ./platform/mobile
	$(MAKE) android-deploy

# Deploy AAR to app/android/app/libs/ + assert 3 ABI present.
# Defends against the recurring incident where a local single-ABI dev build
# overwrites the canonical 3-ABI release in the deploy path, silently
# producing APKs that crash on arm devices with UnsatisfiedLinkError.
#
# Windows-эквивалент — scripts/verify-aar-abi.ps1: этот Makefile не запускается
# под Windows_NT (см. верх файла), а рецепты ниже требуют unzip/sha256sum.
# Правя гейт здесь — правь и там, проверки должны совпадать.
#
# 2026-07-19: убрано мёртвое первое присваивание ABI_COUNT (unzip -p | strings |
# grep -c), которое тут же затиралось следующей строкой и вводило в заблуждение
# при чтении — считалось, что проверок две, а работала всегда только вторая.
.PHONY: android-deploy
android-deploy:
	@if [ ! -f $(BINDIR)/$(LIBNAME).aar ]; then \
		echo "ERROR: $(BINDIR)/$(LIBNAME).aar not found — run 'make android' first"; \
		exit 1; \
	fi
	@ABI_COUNT=$$(unzip -l $(BINDIR)/$(LIBNAME).aar | grep -E 'jni/.*libinhive-core\.so' | wc -l); \
	if [ "$$ABI_COUNT" -ne 3 ]; then \
		echo "ERROR: Source AAR has $$ABI_COUNT ABI(s), expected 3 (arm64-v8a + armeabi-v7a + x86_64). Refusing to deploy."; \
		unzip -l $(BINDIR)/$(LIBNAME).aar | grep 'libinhive-core\.so' || true; \
		exit 1; \
	fi
	@cp $(BINDIR)/$(LIBNAME).aar ../app/android/app/libs/$(LIBNAME).aar
	@DEPLOYED_ABIS=$$(unzip -l ../app/android/app/libs/$(LIBNAME).aar | grep -E 'jni/.*libinhive-core\.so' | wc -l); \
	if [ "$$DEPLOYED_ABIS" -ne 3 ]; then \
		echo "ERROR: Deployed AAR has $$DEPLOYED_ABIS ABI(s) after copy — filesystem issue?"; \
		exit 1; \
	fi
	@SRC_HASH=$$(sha256sum $(BINDIR)/$(LIBNAME).aar | cut -d' ' -f1); \
	DST_HASH=$$(sha256sum ../app/android/app/libs/$(LIBNAME).aar | cut -d' ' -f1); \
	if [ "$$SRC_HASH" != "$$DST_HASH" ]; then \
		echo "ERROR: SHA256 mismatch source vs deploy"; \
		exit 1; \
	fi
	@echo "OK AAR deployed: 3 ABIs verified, SHA256 match"
	@unzip -l ../app/android/app/libs/$(LIBNAME).aar | grep -E 'jni/.*libinhive-core\.so'

ios: lib_install
	gomobile bind -v \
		-target $(IOS_TARGET) \
		-libname=inhive-core \
		-tags=$(IOS_TAGS),$(IOS_ADD_TAGS) \
		-trimpath \
		-ldflags="$(LDFLAGS)" \
		-o $(BINDIR)/InhiveCore.xcframework \
		github.com/sagernet/sing-box/experimental/libbox ./platform/mobile
	cp Info.plist $(BINDIR)/InhiveCore.xcframework/
	$(MAKE) ios-deploy

# Deploy iOS xcframework to app/ios/Frameworks (mirrors android-deploy pattern).
# Build 44 (2026-05-10): добавлен auto-flatten через fix_xcframework_ios.sh.
# gomobile bind v0.1.12 создаёт macOS-style deep bundle (Versions/A/...),
# iOS требует shallow bundle (Info.plist на root). Без fix flutter build ipa
# fail с "expected Info.plist at the root level since the platform uses shallow
# bundles". Подробно в feedback_build_ios_cronet_purego.md.
.PHONY: ios-deploy
ios-deploy:
	@if [ ! -d $(BINDIR)/InhiveCore.xcframework ]; then \
		echo "ERROR: $(BINDIR)/InhiveCore.xcframework not found - run 'make ios' first"; \
		exit 1; \
	fi
	@rm -rf ../app/ios/Frameworks/InhiveCore.xcframework
	@cp -R $(BINDIR)/InhiveCore.xcframework ../app/ios/Frameworks/InhiveCore.xcframework
	@echo "OK xcframework deployed to app/ios/Frameworks/"
	@bash scripts/fix_xcframework_ios.sh
	@echo "OK xcframework flattened (deep -> shallow bundle for iOS)"


# webui target dropped — у InHive нативный Flutter UI поверх gRPC, Clash web-panel
# не используется. Если когда-нибудь понадобится — взять upstream MetaCubeX/Yacd-meta.

# Канонический путь, откуда CMake забирает нативные DLL в Release-бандл:
# app/windows/CMakeLists.txt:87-93 ставит inhive-core.dll, libcronet.dll и
# wintun.dll именно из ../app/inhive-core/bin. Класть DLL в core/bin/ и считать
# дело сделанным — нельзя, CMake туда не смотрит.
APP_CORE_BIN=../app/inhive-core/bin
CRONET_WIN_SLICE=github.com/sagernet/cronet-go/lib/windows_amd64

# windows-naive-lib — синхронизация libcronet.dll с пином из go.mod.
#
# ПОЧЕМУ ЭТО ОТДЕЛЬНЫЙ ОБЯЗАТЕЛЬНЫЙ ШАГ, А НЕ ЧАСТЬ go build:
# на Windows (и только там — WINDOWS_ADD_TAGS=with_purego) cronet НЕ линкуется в
# inhive-core.dll статически. cronet-go под with_purego грузит библиотеку в
# РАНТАЙМЕ: internal/cronet/loader_windows.go:findLibrary() ищет "libcronet.dll"
# рядом с exe и по PATH, дальше syscall.LoadLibrary + GetProcAddress по каждому
# Cronet_*-символу. Отсюда два следствия:
#   1) go build НИКОГДА не падает из-за libcronet.dll — компилятор про него
#      не знает. Ошибка вылезает только у пользователя.
#   2) Ошибка вылезает не «при первом использовании naive» вообще, а в
#      NewNaiveClient → checkLibrary (cronet-go/naive_client.go:97-100), то есть
#      при СОЗДАНИИ naive-outbound'а: "cronet: library not found".
# Хуже полного отсутствия — version skew: файл на месте, но собран под другую
# ревизию Chromium, чем Go-код. Символы резолвятся по имени, ABI разъезжается
# молча. Ровно это случилось 2026-07-05 (релиз 4.7.0): Go-код был на Chromium
# 148, а libcronet.dll в инсталляторе — 143. Test-Path такое не ловит,
# поэтому ниже сверяются именно версии, а не факт существования файла.
#
# Источник истины — go.mod (пин lib-слайса), а не захардкоженная псевдоверсия:
# `go list -m -f {{.Dir}}` разрешает её через модульный кэш, offline, и сам
# едет за любым бампом cronet-go.
.PHONY: windows-naive-lib
windows-naive-lib:
	@set -e; \
	SLICE_DIR=$$(go list -m -f '{{.Dir}}' $(CRONET_WIN_SLICE) 2>/dev/null); \
	if [ -z "$$SLICE_DIR" ] || [ ! -f "$$SLICE_DIR/libcronet.dll" ]; then \
		echo "ERROR: не найден libcronet.dll в слайсе $(CRONET_WIN_SLICE)."; \
		echo "       Прогрейте модульный кэш: go mod download $(CRONET_WIN_SLICE)"; \
		exit 1; \
	fi; \
	mkdir -p $(APP_CORE_BIN); \
	SRC_VER=$$(grep -a -o -E '1[0-9]{2}\.0\.[0-9]{4}\.[0-9]+' "$$SLICE_DIR/libcronet.dll" | sort -u | head -1); \
	if [ -z "$$SRC_VER" ]; then \
		echo "ERROR: не удалось прочитать версию Chromium из слайса — формат libcronet.dll изменился?"; \
		exit 1; \
	fi; \
	cp -f "$$SLICE_DIR/libcronet.dll" $(APP_CORE_BIN)/libcronet.dll; \
	chmod u+w $(APP_CORE_BIN)/libcronet.dll; \
	DST_VER=$$(grep -a -o -E '1[0-9]{2}\.0\.[0-9]{4}\.[0-9]+' $(APP_CORE_BIN)/libcronet.dll | sort -u | head -1); \
	if [ "$$SRC_VER" != "$$DST_VER" ]; then \
		echo "ERROR: version skew после копирования: слайс=$$SRC_VER деплой=$$DST_VER"; \
		exit 1; \
	fi; \
	echo "OK libcronet.dll синхронизирован: Chromium $$SRC_VER (пин $$(go list -m -f '{{.Version}}' $(CRONET_WIN_SLICE)))"

.PHONY: build
windows-amd64: prepare windows-naive-lib
	rm -rf $(BINDIR)/*
	go run -v "github.com/sagernet/cronet-go/cmd/build-naive@$(CRONET_GO_VERSION)" extract-lib --target windows/amd64 -o $(BINDIR)/
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc  $(GOBUILDLIB) -tags $(TAGS),$(WINDOWS_ADD_TAGS)   -o $(BINDIR)/$(LIBNAME).dll ./platform/desktop
	# Деплой в путь, который реально читает CMake (см. APP_CORE_BIN выше).
	# extract-lib выше кладёт libcronet в $(BINDIR) — этого мало: CMake берёт
	# файл из $(APP_CORE_BIN). Туда его ставит отдельная цель
	# windows-naive-lib (в prerequisites), она же сверяет версию Chromium с
	# пином go.mod и работает без кросс-тулчейна.
	mkdir -p $(APP_CORE_BIN)
	cp -f $(BINDIR)/$(LIBNAME).dll $(APP_CORE_BIN)/$(LIBNAME).dll
	echo "core built, now building cli" 
	ls -R $(BINDIR)/
	go install -mod=readonly github.com/akavel/rsrc@latest ||echo "rsrc error in installation"
	go run ./cli tunnel exit
	cp $(BINDIR)/$(LIBNAME).dll ./$(LIBNAME).dll
	$$(go env GOPATH)/bin/rsrc -ico ./assets/inhive-cli.ico -o ./cmd/bydll/cli.syso ||echo "rsrc error in syso"
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_LDFLAGS="$(LIBNAME).dll" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME).exe ./cmd/bydll
	rm ./*.dll
	if [ ! -f $(BINDIR)/$(LIBNAME).dll -o ! -f $(BINDIR)/$(CLINAME).exe ]; then \
		echo "Error: $(LIBNAME).dll or $(CLINAME).exe not built"; \
		exit 1; \
	fi

# 	make webui
	



cronet-%:
	$(MAKE) ARCH=$* build-cronet

build-cronet:
# 	rm -rf $(CRONET_DIR)
	git init $(CRONET_DIR) || echo "dir exist"
	cd $(CRONET_DIR) && \
	git remote add origin https://github.com/sagernet/cronet-go.git ||echo "remote exist"; \
	git fetch --depth=1 origin $(CRONET_GO_VERSION) && \
	git checkout FETCH_HEAD && \
	git submodule update --init --recursive --depth=1 && \
	if [ "$${VARIANT}" = "musl" ]; then \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl env > cronet.env; \
	else \
		go run ./cmd/build-naive --target=linux/$(ARCH) download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) env > cronet.env; \
	fi

################################
# Generic Linux Builder
################################
linux-%:
	$(MAKE) ARCH=$* build-linux

define load_cronet_env
set -a; \
while IFS= read -r line; do \
    key=$${line%%=*}; \
    value=$${line#*=}; \
    export "$$key=$$value"; \
	echo "$$key=$$value"; \
done < $(CRONET_DIR)/cronet.env; \
set +a;
endef

build-linux: prepare
	mkdir -p $(BINDIR)/lib

	$(load_cronet_env)
	FINAL_TAGS=$(TAGS); \
	if [ "$${VARIANT}" = "musl" ]; then \
		FINAL_TAGS=$${FINAL_TAGS},with_musl; \
	elif [ "$${VARIANT}" = "purego" ]; then \
		FINAL_TAGS="$${FINAL_TAGS},with_purego"; \
	fi; \
	echo "FinalTags: $$FINAL_TAGS"; \
	GOOS=linux GOARCH=$(ARCH) $(GOBUILDLIB) -tags $${FINAL_TAGS} -o $(BINDIR)/lib/$(LIBNAME).so ./platform/desktop ;\
	
	echo "Core library built, now building CLI with CGO linking to core library"
	mkdir lib
	cp $(BINDIR)/lib/$(LIBNAME).so ./lib/$(LIBNAME).so

	GOOS=linux GOARCH=$(ARCH) CGO_LDFLAGS="./lib/$(LIBNAME).so -Wl,-rpath,\$$ORIGIN/lib -fuse-ld=lld" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	
	rm -rf ./lib/*.so
	chmod +x $(BINDIR)/$(CLINAME)
	if [ ! -f $(BINDIR)/lib/$(LIBNAME).so -o ! -f $(BINDIR)/$(CLINAME) ]; then \
		echo "Error: $(LIBNAME).so or $(CLINAME) not built"; \
		ls -R $(BINDIR); \
		exit 1; \
	fi
# 	make webui


linux-custom: prepare  install_cronet
	mkdir -p $(BINDIR)/
	#env GOARCH=mips $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/
	$(load_cronet_env)
	go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS) -o $(BINDIR)/$(CLINAME) ./cmd/main
	chmod +x $(BINDIR)/$(CLINAME)

macos-amd64:
	env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-amd64.dylib ./platform/desktop
macos-arm64:
	env GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-arm64.dylib ./platform/desktop
	
macos: prepare macos-amd64 macos-arm64 
	
	lipo -create $(BINDIR)/$(LIBNAME)-amd64.dylib $(BINDIR)/$(LIBNAME)-arm64.dylib -output $(BINDIR)/$(LIBNAME).dylib
	cp $(BINDIR)/$(LIBNAME).dylib ./$(LIBNAME).dylib 
	mv $(BINDIR)/$(LIBNAME)-arm64.h $(BINDIR)/desktop.h 
	# env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="bin/$(LIBNAME).dylib"  CGO_ENABLED=1 $(GOBUILDSRV)  -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	# rm ./$(LIBNAME).dylib
	# chmod +x $(BINDIR)/$(CLINAME)

prepare: 
	go mod tidy

clean:
	rm $(BINDIR)/*




.PHONY: release
release: # Create a new tag for release.	
	@bash -c '.github/change_version.sh'
	


