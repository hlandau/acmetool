ifneq ($(NIX_PATH),)
  # NixOS
  DOCBOOK_XSL := $(shell echo "$(buildInputs)" | tr ' ' '\n' | grep docbook)/xml/xsl/docbook
else
  # Alpine
  DOCBOOK_XSL := $(shell echo /usr/share/xml/docbook/xsl-stylesheets-*)
endif

all: out/index.xhtml out/img out/style.css

clean:
	rm -rf tmp out

deploy:
	rsync -rltv --perms=D755,F644 out/ drone@rem.devever.net::doc/acmetool/

out/img: img
	rsync -a "$<"/ "$@"/

out/style.css: style.css out/index.xhtml
	cat out/docbook.css style.css > "$@"

out/index.xhtml: out/index.docbook tmp/acmetool.8.docbook include-man.xsl to-xhtml.xsl
	rm -f docbook-xsl
	ln -s "$(DOCBOOK_XSL)" docbook-xsl
	xsltproc \
	  --stringparam html.stylesheet style.css \
	  --nonet --output "$@" \
	  to-xhtml.xsl "$<"

out/index.docbook: tmp/index.docbook tmp/acmetool.8.docbook include-man.xsl to-xhtml.xsl
	xsltproc --xinclude --xincludestyle --nonet --output "$@" include-man.xsl "$<"

tmp/%.docbook: %.adoc
	mkdir -p tmp
	asciidoctor -r asciidoctor-diagram -b docbook5 -o "$@" "$<"
