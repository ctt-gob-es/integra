@echo off
rem #Dependencia con Lowagie IText 2.2.
call mvn install:install-file -Dfile=./com/lowagie/itext/2.2/itext-2.2.jar -DgroupId=com.lowagie -DartifactId=itext -Dversion=2.2 -Dpackaging=jar
rem #Dependencia con JavaX Activation 1.0.2
call mvn install:install-file -Dfile=./javax/activation/activation/1.0.2/activation-1.0.2.jar -DgroupId=javax.activation -DartifactId=activation -Dversion=1.0.2 -Dpackaging=jar -DpomFile=./javax/activation/activation/1.0.2/activation-1.0.2.pom
rem #Dependencia con Sun JaxWS STAX-EX 2.1.1
call mvn install:install-file -Dfile=./sun-jaxws/stax-ex/2.1.1/stax-ex-2.1.1.jar -DgroupId=sun-jaxws -DartifactId=stax-ex -Dversion=2.1.1 -Dpackaging=jar -DpomFile=./sun-jaxws/stax-ex/2.1.1/stax-ex-2.1.1.pom
rem #Dependencias con Xmlbeans 2.3.0
call mvn install:install-file -Dfile=./org/apache/xmlbeans/xmlbeans-afirma/2_3_0/xmlbeans-afirma-2.3.0.jar -DgroupId=org.apache.xmlbeans -DartifactId=xmlbeans-afirma -Dversion=2.3.0 -Dpackaging=jar -DpomFile=./org/apache/xmlbeans/xmlbeans-afirma/2_3_0/xmlbeans-afirma-2.3.0.pom
call mvn install:install-file -Dfile=./es/gob/afirma/xmlbeans/2_3_0/xmlSchema/2001/xmlSchema-2001.jar -DgroupId=es.gob.afirma.xmlbeans.2_3_0 -DartifactId=xmlSchema -Dversion=2001 -Dpackaging=jar -DpomFile=./es/gob/afirma/xmlbeans/2_3_0/xmlSchema/2001/xmlSchema-2001.pom
call mvn install:install-file -Dfile=./es/gob/afirma/xmlbeans/2_3_0/XMLDSig/2000v09/XMLDSig-2000v09.jar -DgroupId=es.gob.afirma.xmlbeans.2_3_0 -DartifactId=XMLDSig -Dversion=2000v09 -Dpackaging=jar -DpomFile=./es/gob/afirma/xmlbeans/2_3_0/XMLDSig/2000v09/XMLDSig-2000v09.pom
call mvn install:install-file -Dfile=./es/gob/afirma/xmlbeans/2_3_0/XAdES/01903v132/XAdES-01903v132.jar -DgroupId=es.gob.afirma.xmlbeans.2_3_0 -DartifactId=XAdES -Dversion=01903v132 -Dpackaging=jar -DpomFile=./es/gob/afirma/xmlbeans/2_3_0/XAdES/01903v132/XAdES-01903v132.pom
call mvn install:install-file -Dfile=./es/gob/afirma/xmlbeans/2_3_0/afirmaSchemaXMLTSLv5/119612v020101/afirmaSchemaXMLTSLv5-119612v020101.jar -DgroupId=es.gob.afirma.xmlbeans.2_3_0 -DartifactId=afirmaSchemaXMLTSLv5 -Dversion=119612v020101 -Dpackaging=jar -DpomFile=./es/gob/afirma/xmlbeans/2_3_0/afirmaSchemaXMLTSLv5/119612v020101/afirmaSchemaXMLTSLv5-119612v020101.pom
call mvn install:install-file -Dfile=./es/gob/afirma/xmlbeans/2_3_0/afirmaSchemaXMLTSLv5/119612v020101/afirmaSchemaXMLTSLv5-119612v020101-sources.jar -DgroupId=es.gob.afirma.xmlbeans.2_3_0 -DartifactId=afirmaSchemaXMLTSLv5 -Dversion=119612v020101 -Dpackaging=jar -Dclassifier=sources
