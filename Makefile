acme.html: acme.md
	pandoc -s --toc -c style.css ./acme.md -o acme.html
