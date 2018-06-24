ifneq ($(NIX_PATH),)
  # NixOS
  DOCBOOK_XSL := $(shell echo "$(buildInputs)" | tr ' ' '\n' | grep docbook)/xml/xsl/docbook
else
  # Alpine
  DOCBOOK_XSL := $(shell echo /usr/share/xml/docbook/xsl-stylesheets-*)
endif

all: out/index.xhtml out/man.xhtml out/index.pdf out/man.pdf

clean:
	rm -rf tmp out

deploy:
	rsync -rltv --perms=D755,F644 out/ drone@rem.devever.net::doc/acmetool/

out/%.xhtml: out/%.docbook
	xsltproc \
	  --nonet --output "$@" \
	  $(DOCBOOK_XSL)/xhtml5/docbook.xsl "$<"

out/%.docbook: %.adoc
	mkdir -p out
	asciidoctor -r asciidoctor-diagram -b docbook5 -o "$@" "$<"

out/%.pdf: %.adoc
	mkdir -p out
	asciidoctor -r asciidoctor-pdf -b pdf -o "$@" "$<"
