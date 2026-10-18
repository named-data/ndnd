<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html" encoding="UTF-8" doctype-system="about:legacy-compat"/>

<xsl:template match="/">
  <html>
  <head>
    <meta charset="utf-8"/>
    <title>NDNd Status</title>
    <style>
      body { background:#fff; color:#000; font-family:sans-serif; }
      header, article, footer { display:block; width:90%; margin:20px auto; }
      header h1 { border-bottom:2px solid #99ccb2; padding:0 0 10px; }
      h2 { color:#333; font-size:1.25em; margin:24px 0 8px; }
      .item-list { border-collapse:collapse; margin:10px 0; width:100%; text-align:left; }
      .item-list th { background:#eaf4ef; border-top:1px solid #99ccb2; color:#727272; font-weight:normal; padding:6px; }
      .item-list td { border-top:1px solid transparent; border-bottom:1px solid #fff; padding:4px 6px; vertical-align:top; }
      .item-list tbody tr:nth-child(even) { background:#eee; }
      .center td { text-align:center; }
      .grey { color:#727272; }
      footer { border-top:1px solid #ddd; color:#727272; font-size:.9em; text-align:right; }
      .empty { color:#727272; font-style:italic; }
    </style>
  </head>
  <body>
  <header><h1>NDNd Status</h1></header>
  <article>
    <xsl:apply-templates select="ndndStatus/general"/>
    <xsl:apply-templates select="ndndStatus/channels"/>
    <xsl:apply-templates select="ndndStatus/faces"/>
    <xsl:apply-templates select="ndndStatus/fib"/>
    <xsl:apply-templates select="ndndStatus/rib"/>
    <xsl:apply-templates select="ndndStatus/contentStore"/>
    <xsl:apply-templates select="ndndStatus/strategies"/>
    <xsl:apply-templates select="ndndStatus/bift"/>
    <xsl:apply-templates select="ndndStatus/pet"/>
    <xsl:apply-templates select="ndndStatus/dv"/>
    <xsl:if test="ndndStatus/@dvState='unavailable'">
      <h2>DV Router</h2><p class="empty">DV status is unavailable.</p>
    </xsl:if>
  </article>
  <footer>
    <span class="grey">NDNd status generated <xsl:value-of select="ndndStatus/@generatedAt"/>.</span>
  </footer>
  </body>
  </html>
</xsl:template>

<xsl:template match="general">
  <h2>General Status</h2>
  <table class="item-list"><tbody>
    <tr><th>Version</th><td><xsl:value-of select="version"/></td><th>Start time</th><td><xsl:value-of select="startTime"/></td></tr>
    <tr><th>Current time</th><td><xsl:value-of select="currentTime"/></td><th>Uptime</th><td><xsl:value-of select="uptime"/></td></tr>
    <tr><th>FIB entries</th><td><xsl:value-of select="nFibEntries"/></td><th>PIT entries</th><td><xsl:value-of select="nPitEntries"/></td></tr>
    <tr><th>CS entries</th><td><xsl:value-of select="nContentStoreEntries"/></td><th>In Interests</th><td><xsl:value-of select="nInInterests"/></td></tr>
    <tr><th>Out Interests</th><td><xsl:value-of select="nOutInterests"/></td><th>In Data</th><td><xsl:value-of select="nInData"/></td></tr>
    <tr><th>Out Data</th><td><xsl:value-of select="nOutData"/></td><th>Satisfied Interests</th><td><xsl:value-of select="nSatisfiedInterests"/></td></tr>
    <tr><th>Unsatisfied Interests</th><td><xsl:value-of select="nUnsatisfiedInterests"/></td><td></td><td></td></tr>
  </tbody></table>
</xsl:template>

<xsl:template match="channels">
  <h2>Configured Channels</h2>
  <table class="item-list"><thead><tr><th>Local URI</th></tr></thead><tbody>
    <xsl:for-each select="channel"><tr><td><xsl:value-of select="localUri"/></td></tr></xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="faces">
  <h2>Faces</h2>
  <table class="item-list"><thead><tr>
    <th>ID</th><th>Remote URI</th><th>Local URI</th><th>Scope</th><th>Persistency</th>
    <th>Link type</th><th>MTU</th><th>Flags</th><th>Expiration period (ms)</th><th>In Interests</th><th>In Data</th>
    <th>In Bytes</th><th>Out Interests</th><th>Out Data</th><th>Out Bytes</th>
  </tr></thead><tbody><xsl:for-each select="face"><tr>
    <td><xsl:value-of select="@faceId"/></td><td><xsl:value-of select="remoteUri"/></td>
    <td><xsl:value-of select="localUri"/></td><td><xsl:value-of select="scope"/></td>
    <td><xsl:value-of select="persistency"/></td><td><xsl:value-of select="linkType"/></td>
    <td><xsl:value-of select="mtu"/></td><td><xsl:value-of select="flags"/></td>
    <td><xsl:choose><xsl:when test="expirationMilliseconds"><xsl:value-of select="expirationMilliseconds"/></xsl:when><xsl:otherwise>not set</xsl:otherwise></xsl:choose></td>
    <td><xsl:value-of select="nInInterests"/></td><td><xsl:value-of select="nInData"/></td>
    <td><xsl:value-of select="nInBytes"/></td><td><xsl:value-of select="nOutInterests"/></td>
    <td><xsl:value-of select="nOutData"/></td><td><xsl:value-of select="nOutBytes"/></td>
  </tr></xsl:for-each></tbody></table>
</xsl:template>

<xsl:template match="fib">
  <h2>FIB</h2><table class="item-list"><thead><tr><th>Prefix</th><th>Next hops</th></tr></thead><tbody>
    <xsl:for-each select="entry"><tr><td><xsl:value-of select="@prefix"/></td><td>
      <xsl:for-each select="nextHop">face <xsl:value-of select="@faceId"/> (cost <xsl:value-of select="@cost"/>)<br/></xsl:for-each>
    </td></tr></xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="rib">
  <h2>RIB</h2><table class="item-list"><thead><tr><th>Prefix</th><th>Face</th><th>Origin</th><th>Cost</th><th>Flags</th><th>Expiry (ms)</th></tr></thead><tbody>
    <xsl:for-each select="entry"><xsl:variable name="prefix" select="@prefix"/>
      <xsl:for-each select="route"><tr><td><xsl:value-of select="$prefix"/></td><td><xsl:value-of select="@faceId"/></td>
        <td><xsl:value-of select="@origin"/></td><td><xsl:value-of select="@cost"/></td><td><xsl:value-of select="@flags"/></td>
        <td><xsl:value-of select="@expirationMilliseconds"/></td></tr></xsl:for-each>
    </xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="contentStore">
  <h2>Content Store</h2><table class="item-list"><thead><tr>
    <th>Capacity</th><th>Admit</th><th>Serve</th><th>Entries</th><th>Hits</th><th>Misses</th>
  </tr></thead><tbody><tr><td><xsl:value-of select="@capacity"/></td><td><xsl:value-of select="@admit"/></td>
    <td><xsl:value-of select="@serve"/></td><td><xsl:value-of select="@entries"/></td>
    <td><xsl:value-of select="@hits"/></td><td><xsl:value-of select="@misses"/></td>
  </tr></tbody></table>
</xsl:template>

<xsl:template match="strategies">
  <h2>Strategy Choices</h2><table class="item-list"><thead><tr><th>Prefix</th><th>Strategy</th></tr></thead><tbody>
    <xsl:for-each select="strategy"><tr><td><xsl:value-of select="@prefix"/></td><td><xsl:value-of select="@strategy"/></td></tr></xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="bift">
  <h2>BIFT</h2><p>Schema version: <xsl:value-of select="@version"/>; BIER index: <xsl:choose><xsl:when test="@bierIndex"><xsl:value-of select="@bierIndex"/></xsl:when><xsl:otherwise>disabled</xsl:otherwise></xsl:choose></p>
  <table class="item-list"><thead><tr><th>BFR-ID</th><th>Router</th><th>Next hops</th><th>Forwarding bits</th></tr></thead><tbody>
    <xsl:for-each select="entry"><tr><td><xsl:value-of select="@bfrId"/></td><td><xsl:value-of select="@routerName"/></td>
      <td><xsl:for-each select="nextHop"><xsl:value-of select="."/><xsl:if test="position()!=last()">, </xsl:if></xsl:for-each></td>
      <td><xsl:for-each select="forwardingBit"><xsl:value-of select="."/><xsl:if test="position()!=last()">, </xsl:if></xsl:for-each></td>
    </tr></xsl:for-each>
  </tbody></table>
  <h3>BIFT Neighbors</h3><table class="item-list"><thead><tr><th>Face ID</th><th>Forwarding bits</th></tr></thead><tbody>
    <xsl:for-each select="neighbor"><tr><td><xsl:value-of select="@faceId"/></td><td>
      <xsl:for-each select="forwardingBit"><xsl:value-of select="."/><xsl:if test="position()!=last()">, </xsl:if></xsl:for-each>
    </td></tr></xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="pet">
  <h2>Prefix Egress Table</h2><table class="item-list"><thead><tr><th>Prefix</th><th>Multicast</th><th>Egress routers</th><th>Next hops</th></tr></thead><tbody>
    <xsl:for-each select="entry"><tr><td><xsl:value-of select="@prefix"/></td><td><xsl:value-of select="@multicast"/></td>
      <td><xsl:for-each select="egress"><xsl:value-of select="."/><xsl:if test="position()!=last()">, </xsl:if></xsl:for-each></td>
      <td><xsl:for-each select="nextHop">face <xsl:value-of select="@faceId"/> (cost <xsl:value-of select="@cost"/>)<br/></xsl:for-each></td>
    </tr></xsl:for-each>
  </tbody></table>
</xsl:template>

<xsl:template match="dv">
  <h2>Distance Vector</h2><table class="item-list"><thead><tr><th>Version</th><th>Network</th><th>Router</th><th>RIB entries</th><th>Neighbors</th><th>FIB entries</th><th>Prefix state entries</th></tr></thead><tbody>
    <tr><td><xsl:value-of select="@version"/></td><td><xsl:value-of select="@networkName"/></td><td><xsl:value-of select="@routerName"/></td>
      <td><xsl:value-of select="@ribEntries"/></td><td><xsl:value-of select="@neighbors"/></td><td><xsl:value-of select="@fibEntries"/></td><td><xsl:value-of select="@prefixStateEntries"/></td>
    </tr>
  </tbody></table>
  <h3>DV Prefix State</h3>
  <xsl:choose>
    <xsl:when test="@prefixListState='available'">
      <xsl:choose>
        <xsl:when test="prefixState/entry">
          <table class="item-list"><thead><tr><th>Prefix</th><th>Router</th><th>Multicast</th><th>Validity</th><th>Next hops</th></tr></thead><tbody>
            <xsl:for-each select="prefixState/entry"><tr>
              <td><xsl:value-of select="@prefix"/></td><td><xsl:value-of select="@router"/></td><td><xsl:value-of select="@multicast"/></td>
              <td><xsl:choose>
                <xsl:when test="validity/notBefore and validity/notAfter"><xsl:value-of select="validity/notBefore"/> – <xsl:value-of select="validity/notAfter"/></xsl:when>
                <xsl:when test="validity/notBefore">from <xsl:value-of select="validity/notBefore"/></xsl:when>
                <xsl:when test="validity/notAfter">until <xsl:value-of select="validity/notAfter"/></xsl:when>
                <xsl:otherwise>unbounded</xsl:otherwise>
              </xsl:choose></td>
              <td><xsl:for-each select="nextHop">face <xsl:value-of select="@faceId"/> (cost <xsl:value-of select="@cost"/>)<br/></xsl:for-each></td>
            </tr></xsl:for-each>
          </tbody></table>
        </xsl:when>
        <xsl:otherwise><p class="empty">No prefix-state entries.</p></xsl:otherwise>
      </xsl:choose>
    </xsl:when>
    <xsl:otherwise><p class="empty">DV prefix state is unavailable.</p></xsl:otherwise>
  </xsl:choose>
</xsl:template>
</xsl:stylesheet>