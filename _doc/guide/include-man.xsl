<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml" version="1.0" xmlns:db="http://docbook.org/ns/docbook" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xsl:output method="xml" />

  <xsl:template match="node()|@*">
    <xsl:copy>
      <xsl:apply-templates select="node()|@*"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="/db:book">
    <xsl:copy>
      <xsl:apply-templates select="node()" />
      <db:reference xml:id="manpages">
        <db:title>Manual Pages</db:title>
        <xi:include href="tmp/acmetool.8.docbook" />
      </db:reference>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
