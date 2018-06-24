<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml" version="1.0">
  <xsl:import href="docbook-xsl/xhtml5/docbook.xsl" />

  <xsl:param name="generate.toc">
    book toc
  </xsl:param>

  <xsl:param name="part.autolabel">0</xsl:param>
  <xsl:param name="reference.autolabel">0</xsl:param>

  <xsl:template name="user.head.content">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes" />
  </xsl:template>

  <xsl:template name="user.header.content">
    <div id="logo">
      <h1><a href="."><img src="img/acmetool-logo-black.png" alt="acmetool - Let's Encrypt Client" /></a></h1>
    </div>
    <nav id="tnav">
    <ul>
      <li><a href=".">User's Guide</a></li>
      <li><a href="https://git.devever.net/hlandau/acmetool/src/branch/master/README.md">README</a></li>
      <li><a href="https://git.devever.net/hlandau/acmetool/releases">Download Binaries</a></li>
      <li><a href="https://git.devever.net/hlandau/acmetool">Source Code</a></li>
    </ul>
    </nav>
  </xsl:template>

</xsl:stylesheet>
