all: userguide.html index.html acmetool.8.html

clean:
	rm userguide.html acmetool.8.html

%.html: %.md pandoc.tpl
	pandoc -s --toc -c style.css "$<" --template pandoc.tpl -V docid:$(shell echo "$@" | sed 's/\.[a-z]*$$//g') -o "$@"

acmetool.8.html:
	acmetool --help-man | ./roffit/roffit --bare > "$@.tmp"
	pandoc -s -c style.css "$@.tmp" --template pandoc.tpl -V docid:manpage -o "$@"
	-rm "$@.tmp"
