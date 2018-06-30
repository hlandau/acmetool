PROJNAME=git.devever.net/hlandau/acmetool
BINARIES=$(PROJNAME)

###############################################################################
# v1.12  NNSC:github.com/hlandau/degoutils/_stdenv/Makefile.ref
# This is a standard Makefile for building Go code designed to be copied into
# other projects. Code below this line is not intended to be modified.
#
# NOTE: Use of this Makefile is not mandatory. People familiar with the use
# of the "go" command who have a GOPATH setup can use go get/go install.

# XXX: prebuild-checks needs bash, fix this at some point
SHELL := $(shell which bash)

-include Makefile.extra
-include Makefile.assets

## Paths
ifeq ($(GOPATH),)
# for some reason export is necessary for FreeBSD's gmake
export GOPATH := $(shell pwd)
endif
ifeq ($(GOBIN),)
export GOBIN := $(GOPATH)/bin
endif
ifeq ($(PREFIX),)
export PREFIX := /usr/local
endif

DIRS=src bin public

## Quieting
Q=@
QI=@echo -e "\t[$(1)]\t  $(2)";
ifeq ($(V),1)
	Q=
	QI=
endif

## Buildinfo
ifeq ($(USE_BUILDINFO),1)
	BUILDINFO_FLAG=-ldflags "$$($$GOPATH/src/github.com/hlandau/buildinfo/gen $(1))"
endif

## Standard Rules
all: prebuild-checks $(DIRS)
	$(call QI,GO-INSTALL,$(BINARIES))go install $(BUILDFLAGS) $(call BUILDINFO_FLAG,$(BINARIES)) $(BINARIES)

prebuild-checks:
	$(call QI,RELOCATE)if [ `find . -iname '*.go' | grep -v ./src/ | wc -l` != 0 ]; then \
		if [ -e "$(GOPATH)/src/$(PROJNAME)/" ]; then \
			echo "$$GOPATH/src/$(PROJNAME)/ already exists, can't auto-relocate. Since you appear to have a GOPATH configured, just use go get -u '$(PROJNAME)/...; go install $(BINARIES)'. Alternatively, move this Makefile to either GOPATH or an empty directory outside GOPATH (preferred) and run it. Or delete '$$GOPATH/src/$(PROJNAME)/'."; \
			exit 1; \
		fi; \
		mkdir -p "$(GOPATH)/src/$(PROJNAME)/"; \
		for x in ./* ./.*; do \
			[ "$$x" == "./src" ] && continue; \
			mv -n "$$x" "$(GOPATH)/src/$(PROJNAME)/"; \
		done; \
		ln -s "$(GOPATH)/src/$(PROJNAME)/Makefile"; \
		[ -e "$(GOPATH)/src/$(PROJNAME)/_doc" ] && ln -s "$(GOPATH)/src/$(PROJNAME)/_doc" doc; \
		[ -e "$(GOPATH)/src/$(PROJNAME)/_tpl" ] && ln -s "$(GOPATH)/src/$(PROJNAME)/_tpl" tpl; \
	fi; \
	exit 0

$(DIRS): | .gotten
	$(call QI,DIRS)mkdir -p $(GOPATH)/src $(GOBIN); \
  if [ ! -e "src" ]; then \
	  ln -s $(GOPATH)/src src; \
	fi; \
	if [ ! -e "bin" ]; then \
		ln -s $(GOBIN) bin; \
	fi

.gotten:
	$(call QI,GO-GET,$(PROJNAME))go get $(PROJNAME)/...
	$(Q)touch .gotten

.NOTPARALLEL: prebuild-checks $(DIRS)
.PHONY: all test install prebuild-checks

test:
	$(call QI,GO-TEST,$(PROJNAME))for x in $(PROJNAME); do go test -cover -v $$x/...; done

install: all
	$(call QI,INSTALL,$(BINARIES))for x in $(BINARIES); do \
		install -Dp $(GOBIN)/`basename "$$x"` $(DESTDIR)$(PREFIX)/bin; \
	done

update: | .gotten
	$(call QI,GO-GET,$(PROJNAME))go get -u $(PROJNAME)/...
