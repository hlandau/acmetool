ifneq ($(NIX_PATH),)
  # NixOS
  DOCBOOK_XSL := $(shell echo "$(buildInputs)" | tr ' ' '\n' | grep docbook)/xml/xsl/docbook
else
  # Alpine
  DOCBOOK_XSL := $(shell echo /usr/share/xml/docbook/xsl-stylesheets-*)
endif

all: out/index.xhtml

clean:
	rm -rf tmp out

out/index.xhtml: out/index.docbook
	xsltproc \
	  --nonet --output "$@" \
	  $(DOCBOOK_XSL)/xhtml5/docbook.xsl "$<"

out/index.docbook: index.adoc
	mkdir -p out
	asciidoctor -r asciidoctor-diagram -b docbook5 -o "$@" "$<"
