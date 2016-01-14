<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" id="$docid$">
<head>
  <meta charset="utf-8"/>
  <title>$if(pagetitle)$$pagetitle$$else$acmetool$endif$</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes"/>
  <link rel="stylesheet" href="style.css"/>
  $for(header-includes)$ $header-includes$ $endfor$
</head>
<body>
$for(include-before)$
$include-before$
$endfor$

<div id="logo">
  <h1><a href="."><img src="img/acmetool-logo-black.png" alt="acmetool - Let's Encrypt Client" /></a></h1>
</div>
<nav id="tnav">
<ul>
  <li><a href="userguide">User's Guide</a></li>
  <li><a href="acmetool.8">man acmetool</a></li>
  <li><a href="https://github.com/hlandau/acme/blob/master/README.md">README</a></li>
  <li><a href="https://github.com/hlandau/acme/releases">Download Binaries</a></li>
  <li><a href="https://github.com/hlandau/acme">Source Code</a></li>
</ul>
</nav>

<div id="obody">
$if(title)$
<header>
<h1 class="title">$title$</h1>
</header>
$endif$

$if(toc)$
<nav id="$idprefix$TOC">$toc$</nav>
$endif$
$body$
</div>

$for(include-after)$
$include-after$
$endfor$
</body>
</html>
