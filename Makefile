all: userguide.html acmetool.8.html

clean:
	rm userguide.html acmetool.8.html

userguide.html: userguide.md
	pandoc -s --toc -c style.css "$<" -o "$@"

acmetool.8.html:
	acmetool --help-man | ./roffit/roffit > "$@"
