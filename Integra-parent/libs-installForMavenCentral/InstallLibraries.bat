@echo off
rem #Dependencia con Lowagie IText 2.2.
call mvn install:install-file -Dfile=./com/lowagie/itext/2.2/itext-2.2.jar -DgroupId=com.lowagie -DartifactId=itext -Dversion=2.2 -Dpackaging=jar
rem #Dependencia con JavaX Activation 1.0.2
call mvn install:install-file -Dfile=./javax/activation/activation/1.0.2/activation-1.0.2.jar -DgroupId=javax.activation -DartifactId=activation -Dversion=1.0.2 -Dpackaging=jar -DpomFile=./javax/activation/activation/1.0.2/activation-1.0.2.pom
rem #Dependencia con Sun JaxWS STAX-EX 2.1.1
call mvn install:install-file -Dfile=./sun-jaxws/stax-ex/2.1.1/stax-ex-2.1.1.jar -DgroupId=sun-jaxws -DartifactId=stax-ex -Dversion=2.1.1 -Dpackaging=jar -DpomFile=./sun-jaxws/stax-ex/2.1.1/stax-ex-2.1.1.pom
rem #Dependencias con Xmlbeans 2.3.0
call mvn install:install-file -Dfile="./es/gob/afirma/xmlbeans/2_3_0/afirmaSchemaXMLTSLv6/119612v020301/valet-afirmaSchemaXMLTSLv6.jar" -DpomFile="./es/gob/afirma/xmlbeans/2_3_0/afirmaSchemaXMLTSLv6/119612v020301/valet-afirmaSchemaXMLTSLv6.pom" -DgroupId=es.gob.valet -DartifactId=valet-afirmaSchemaXMLTSLv6 -Dversion=1.2.0 -Dpackaging=jar
rem #Dependencia con Barcode4j v 2.1 
call mvn install:install-file -Dfile=./net/sf/barcode4j/barcode4j-fop-ext-complete/2.1/barcode4j-fop-ext-complete-2.1.jar -DgroupId=net.sf.barcode4j -DartifactId=barcode4j-fop-ext-complete -Dversion=2.1 -Dpackaging=jar -DpomFile=./net/sf/barcode4j/barcode4j-fop-ext-complete/2.1/barcode4j-fop-ext-complete-2.1.pom
