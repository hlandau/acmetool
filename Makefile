userguide.html: userguide.md
	pandoc -s --toc -c style.css "$<" -o "$@"
