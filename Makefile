userguide.html: userguide.md
	pandoc -s --toc -c style.css "$<" -o "$@"

acmetool.8.html:
	acmetool --help-man | ./roffit/roffit > "$@"
