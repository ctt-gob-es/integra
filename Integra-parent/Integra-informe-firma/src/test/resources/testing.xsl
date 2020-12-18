<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
	xmlns:ri="urn:es:gob:signaturereport:generation:inputparameters"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<xsl:output method="xml" version="1.0" omit-xml-declaration="no"
		indent="yes" encoding="UTF-8" />
	<xsl:template match="ri:GenerationReport">
		<fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
			<fo:layout-master-set>
				<fo:simple-page-master master-name="simple"
					page-height="29.7cm" page-width="21cm" margin-top="0.5cm"
					margin-bottom="0.5cm" margin-left="0.5cm" margin-right="0.5cm">
					<fo:region-body margin-top="2cm" margin-bottom="2cm"
						margin-right="2cm" margin-left="2cm" />
					<fo:region-before extent="2cm" />
					<fo:region-after extent="1cm" />
					<fo:region-start extent="2cm" />
					<fo:region-end extent="1cm" />
				</fo:simple-page-master>
			</fo:layout-master-set>
			<xsl:variable name="externalReference"
				select="ri:ExternalParameters/ri:Parameter[ri:ParameterId='externalReference']/ri:ParameterValue" />
			<xsl:variable name="includeDocInfo" select="count(ri:DocumentInfo)" />
			<xsl:variable name="numTotalPages" select="ri:DocumentInfo/ri:NumPages" />
			<xsl:variable name="iniPage" select="0" />
			<xsl:variable name="signersNumber" select="count(//ri:CertificateInfo)" />
			<xsl:variable name="srcImagenGobierno"
				select="ri:ExternalParameters/ri:Parameter[ri:ParameterId='uriLogoMinisterio']/ri:ParameterValue"/>
			<xsl:variable name="srcImagenAplicacion"
				select="ri:ExternalParameters/ri:Parameter[ri:ParameterId='urlBytesLogoAfirma']/ri:ParameterValue"/>
			<xsl:if test="$includeDocInfo!=0">
				<xsl:call-template name="pageSequenceWithDocument">
					<xsl:with-param name="externalReference">
						<xsl:value-of select="$externalReference" />
					</xsl:with-param>
					<xsl:with-param name="srcImagenGobierno">
						<xsl:value-of select="$srcImagenGobierno" />
					</xsl:with-param>
					<xsl:with-param name="srcImagenAplicacion">
						<xsl:value-of select="$srcImagenAplicacion" />
					</xsl:with-param>
					<xsl:with-param name="currentPage">
						<xsl:value-of select="$iniPage" />
					</xsl:with-param>
					<xsl:with-param name="numPages">
						<xsl:value-of select="$numTotalPages" />
					</xsl:with-param>
					<xsl:with-param name="signersNumber">
						<xsl:value-of select="$signersNumber" />
					</xsl:with-param>
				</xsl:call-template>
			</xsl:if>
		</fo:root>
	</xsl:template>
	<!-- Se tiene información del documento firmado -->
	<xsl:template name="pageSequenceWithDocument">
		<xsl:param name="externalReference" />
		<xsl:param name="srcImagenGobierno" />
		<xsl:param name="srcImagenAplicacion" />
		<xsl:param name="currentPage" />
		<xsl:param name="numPages" />
		<xsl:param name="signersNumber" />
		<xsl:if test="$currentPage &lt; $numPages">
			<ri:IncludePage Ypos="30" Xpos="30" Width="150"
				Height="230">
				<ri:DocumentPage>
					<xsl:value-of select="$currentPage + 1" />
				</ri:DocumentPage>
				<ri:ReportPage>
					<xsl:value-of select="$currentPage + 1" />
				</ri:ReportPage>
			</ri:IncludePage>
			<fo:page-sequence master-reference="simple">
				<fo:static-content flow-name="xsl-region-start">
					<fo:block-container reference-orientation="90">
						<fo:block font-size="6pt">
							<fo:table>
								<fo:table-body>
									<fo:table-row>
										<!-- Información del firmante -->
										<xsl:for-each select="//ri:IndividualSignature">
											<xsl:variable name="fecha"
												select="substring(ri:TimeStamp,0,11)" />
											<xsl:variable name="nombre"
												select="ri:CertificateInfo/ri:Field[ri:FieldId='nombreResponsable']/ri:FieldValue" />
											<xsl:variable name="primerApellido"
												select="ri:CertificateInfo/ri:Field[ri:FieldId='primerApellidoResponsable']/ri:FieldValue" />
											<xsl:variable name="segundoApellido"
												select="ri:CertificateInfo/ri:Field[ri:FieldId='segundoApellidoResponsable']/ri:FieldValue" />
											<xsl:variable name="dni"
												select="ri:CertificateInfo/ri:Field[ri:FieldId='NIFResponsable']/ri:FieldValue" />
											<xsl:variable name="emisor"
												select="ri:CertificateInfo/ri:Field[ri:FieldId='emisor']/ri:FieldValue" />
											<xsl:variable name="espacio" select="' '" />
											<fo:table-cell width="8cm">
												<fo:block>
													<fo:table>
														<fo:table-body>
															<fo:table-row>
																<fo:table-cell>
																	<fo:block>
																		<fo:table>
																			<fo:table-body>
																				<fo:table-row>
																					<fo:table-cell text-align="left"
																						width="2cm">
																						<fo:block>
																							<xsl:value-of select="$fecha" />
																						</fo:block>
																						<fo:block>
																							<xsl:value-of select="$dni" />
																						</fo:block>
																					</fo:table-cell>
																					<fo:table-cell text-align="left">
																						<fo:block text-align="left">
																							<fo:instream-foreign-object>
																								<barcode:barcode
																									xmlns:barcode="http://barcode4j.krysalis.org/ns">
																									<xsl:attribute name="message"><xsl:value-of select="$dni"/></xsl:attribute>
																									<barcode:pdf417 />
																								</barcode:barcode>
																							</fo:instream-foreign-object>
																						</fo:block>
																					</fo:table-cell>
																				</fo:table-row>
																			</fo:table-body>
																		</fo:table>
																	</fo:block>
																</fo:table-cell>
															</fo:table-row>
															<fo:table-row>
																<fo:table-cell>
																	<fo:block text-align="left">
																		Firmado por:
																		<xsl:value-of select="$primerApellido" />
																		<xsl:value-of select="$espacio" />
																		<xsl:value-of select="$segundoApellido" />
																		,
																		<xsl:value-of select="$espacio" />
																		<xsl:value-of select="$nombre" />
																	</fo:block>
																</fo:table-cell>
															</fo:table-row>
															<fo:table-row>
																<fo:table-cell>
																	<fo:block text-align="left">
																		<xsl:value-of select="$emisor" />
																	</fo:block>
																</fo:table-cell>
															</fo:table-row>
															<fo:table-row>
																<fo:table-cell>
																	<fo:block text-align="left">
																		<xsl:value-of select="$externalReference" />
																	</fo:block>
																</fo:table-cell>
															</fo:table-row>
														</fo:table-body>
													</fo:table>
												</fo:block>
											</fo:table-cell>
										</xsl:for-each>
									</fo:table-row>
								</fo:table-body>
							</fo:table>
						</fo:block>
					</fo:block-container>
				</fo:static-content>
				<fo:static-content flow-name="xsl-region-after">
					<!-- Pie de página -->
					<fo:block />
				</fo:static-content>
				<fo:static-content flow-name="xsl-region-before">
					<fo:block>
						<fo:table>
							<fo:table-body>
								<fo:table-row>
									<fo:table-cell>
										<!-- Bloque destinado al logo del Gobierno -->
										<fo:block>
											<fo:external-graphic content-width="5cm"
												content-height="1.5cm">
												<xsl:attribute name="src">
													<xsl:value-of select="$srcImagenGobierno" />
												</xsl:attribute>
											</fo:external-graphic>
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<!-- Bloque destinado al logo de la aplicación -->
										<fo:block text-align="right">
											<fo:external-graphic content-width="5cm"
												content-height="1.5cm">
												<xsl:attribute name="src">
													<xsl:value-of select="$srcImagenAplicacion" />
												</xsl:attribute>
											</fo:external-graphic>
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</fo:table-body>
						</fo:table>
					</fo:block>
				</fo:static-content>
				<fo:static-content flow-name="xsl-region-end">
					<fo:block>
						<!-- Region de la derecha -->
					</fo:block>
				</fo:static-content>
				<fo:flow flow-name="xsl-region-body">
					<fo:block />
				</fo:flow>
			</fo:page-sequence>
			<xsl:call-template name="pageSequenceWithDocument">
				<xsl:with-param name="externalReference">
					<xsl:value-of select="$externalReference" />
				</xsl:with-param>
				<xsl:with-param name="srcImagenGobierno">
					<xsl:value-of select="$srcImagenGobierno" />
				</xsl:with-param>
				<xsl:with-param name="srcImagenAplicacion">
					<xsl:value-of select="$srcImagenAplicacion" />
				</xsl:with-param>
				<xsl:with-param name="currentPage">
					<xsl:value-of select="$currentPage + 1" />
				</xsl:with-param>
				<xsl:with-param name="numPages">
					<xsl:value-of select="$numPages" />
				</xsl:with-param>
				<xsl:with-param name="signersNumber">
					<xsl:value-of select="$signersNumber" />
				</xsl:with-param>
			</xsl:call-template>
		</xsl:if>
	</xsl:template>
</xsl:stylesheet>